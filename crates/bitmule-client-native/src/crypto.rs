//! End-to-end encryption for bitmule transfers.
//!
//! Threat model + design per Seb 2026-09-02:
//! - `A` is a 32-byte symmetric secret placed in the URL (# fragment, so
//!   the server never sees it). Whichever side initiates the transfer
//!   generates A; the other side learns A by opening the share link.
//! - `session_id` = SHA256(A) is the public identifier the server sees.
//! - Per-session, both peers generate ephemeral X25519 keypairs, exchange
//!   the public halves over the signaling WS, and derive
//!   `S = X25519(local_priv, peer_pub)`.
//! - Each ephemeral pub is authenticated in transit with
//!   `HMAC-SHA256(A, ephemeral_pub)` so a MITM without A cannot inject its
//!   own key.
//! - Sender generates a fresh bulk key `B` (32 bytes), AEAD-wraps it under
//!   S, and sends the wrapped copy over the WS.
//! - File chunks are compressed then AEAD-encrypted under B with a
//!   deterministic nonce derived from the chunk index, then forwarded on
//!   the transport (WebRTC data channel or server-relay HTTP).
//!
//! Forward secrecy: even if A leaks after a session and the network
//! traffic was captured, an attacker still cannot derive S (needs one of
//! the ephemeral privates, which are wiped as soon as S is computed).
//! Same protection covers server-stored relay chunks.

use anyhow::{anyhow, bail, Context, Result};
use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hmac::digest::KeyInit as HmacKeyInit;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::Zeroize;

/// 32-byte URL-shared secret. Session id is SHA256(A), publicly visible.
/// A itself is only ever known to the two endpoints.
#[derive(Clone)]
pub struct ShareKey(pub [u8; 32]);

impl ShareKey {
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        Self(buf)
    }

    /// Sender-initiated commitment: A = SHA256(data || file_key). The URL
    /// becomes a binary-identity binding of (this file, this key), which
    /// receivers can verify post-decrypt. An attacker who somehow
    /// obtains S and can produce a modified data' still cannot forge a
    /// (data', file_key') pair whose SHA-256 equals the original URL —
    /// that would require a preimage attack.
    ///
    /// Only applies to sender-initiated flows (`bitmule send <path>`)
    /// where the file is known at URL-generation time. Receiver-initiated
    /// flows (`bitmule recv`, sender uploads later) use `random()` — no
    /// data commitment possible without knowing the file in advance.
    pub fn from_data_commitment(data: &[u8], file_key: &BulkKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(file_key.0);
        Self(hasher.finalize().into())
    }

    /// Receiver-side verification of the URL commitment. Called after
    /// full decrypt succeeds. Returns true iff `SHA256(data || file_key)`
    /// equals this ShareKey's bytes. Constant-time comparison.
    pub fn verify_data_commitment(&self, data: &[u8], file_key: &BulkKey) -> bool {
        let computed = Self::from_data_commitment(data, file_key);
        constant_time_eq(&self.0, &computed.0)
    }

    /// Hex-encoded, suitable for placement in the share URL's `#` fragment.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        if s.len() != 64 { bail!("share key hex must be 64 chars, got {}", s.len()); }
        let mut buf = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let byte_str = std::str::from_utf8(chunk).context("non-utf8 hex")?;
            buf[i] = u8::from_str_radix(byte_str, 16).context("bad hex byte")?;
        }
        Ok(Self(buf))
    }

    /// Public session identifier the server sees. `SHA256(A)` — one-way,
    /// so leaking session_id doesn't leak A.
    pub fn session_id_hex(&self) -> String {
        let hash = Sha256::digest(self.0);
        hash.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// HMAC-SHA256(A, ephemeral_pub) — authenticates the ephemeral public
    /// during the KEX exchange so a passive listener without A cannot
    /// substitute their own key.
    pub fn mac_ephemeral_pub(&self, pub_bytes: &[u8; 32]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as HmacKeyInit>::new_from_slice(&self.0)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(pub_bytes);
        mac.finalize().into_bytes().into()
    }
}

impl Drop for ShareKey {
    fn drop(&mut self) { self.0.zeroize(); }
}

/// URL-fragment payload: 32-byte `share_key` (URL secret, drives session_id
/// + KEX MAC) followed by 32-byte `signature` (data commitment = SHA256(data
/// || bulk_key)). Encoded as base64url (no padding) in the URL fragment.
///
/// Layout is `share_key || signature`, decoded by taking the first 32 bytes
/// as share_key and the remainder as signature — share_key size is fixed so
/// no length prefix is needed.
#[derive(Clone)]
pub struct ShareLink {
    pub share_key: ShareKey,
    pub signature: [u8; 32],
}

impl ShareLink {
    pub fn new(share_key: ShareKey, signature: [u8; 32]) -> Self {
        Self { share_key, signature }
    }

    /// Base64url-no-pad encoding of `share_key || signature` (64 bytes → 86 chars).
    pub fn to_b64_url(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&self.share_key.0);
        buf[32..].copy_from_slice(&self.signature);
        URL_SAFE_NO_PAD.encode(buf)
    }

    pub fn from_b64_url(s: &str) -> Result<Self> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let raw = URL_SAFE_NO_PAD.decode(s.as_bytes())
            .context("share link is not valid base64url")?;
        if raw.len() != 64 {
            bail!("share link must decode to 64 bytes, got {}", raw.len());
        }
        let mut sk = [0u8; 32];
        let mut sig = [0u8; 32];
        sk.copy_from_slice(&raw[..32]);
        sig.copy_from_slice(&raw[32..]);
        Ok(Self { share_key: ShareKey(sk), signature: sig })
    }

    /// Convenience: verify that this link's signature commits to `data` under
    /// `bulk_key`. Constant-time.
    pub fn verify_signature(&self, data: &[u8], bulk_key: &BulkKey) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(bulk_key.0);
        let computed: [u8; 32] = hasher.finalize().into();
        constant_time_eq(&self.signature, &computed)
    }
}

/// Streaming SHA256(data || bulk_key.0) — for sender-side commitment
/// generation without loading the whole file into memory. Feed the file
/// contents through `update`, then call `finalize` with the bulk key.
pub struct CommitmentHasher {
    inner: Sha256,
}

impl Default for CommitmentHasher {
    fn default() -> Self { Self::new() }
}

impl CommitmentHasher {
    pub fn new() -> Self { Self { inner: Sha256::new() } }
    pub fn update(&mut self, chunk: &[u8]) { self.inner.update(chunk); }
    pub fn finalize(mut self, bulk_key: &BulkKey) -> [u8; 32] {
        self.inner.update(bulk_key.0);
        self.inner.finalize().into()
    }
}

/// Local half of the ephemeral X25519 pair, consumed on `derive_shared_key`.
/// Wraps `EphemeralSecret` from `x25519-dalek` so callers can't accidentally
/// use it twice — the derivation call moves the secret in.
pub struct Ephemeral {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl Ephemeral {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] { *self.public.as_bytes() }

    /// Derive the session shared secret S = X25519(our_priv, peer_pub).
    /// S is the RAW 32-byte X25519 output — non-uniform, don't use as a
    /// symmetric key directly. Feed it into `SessionKey::wrap_key`
    /// with the session's salt to derive a proper symmetric key for
    /// AEAD wrapping of B.
    ///
    /// Consumes the ephemeral secret — forward-secrecy hedge, the
    /// private half can't be reused or exported.
    ///
    /// Rejects malformed `peer_pub`:
    /// - Small-subgroup / low-order points (RFC 7748 §7). These are
    ///   pre-enumerated points that would force the shared secret to
    ///   a value under the attacker's control.
    /// - Post-DH check that the shared secret isn't all zeros (the
    ///   generic form of the small-subgroup catch, in case the
    ///   pre-check missed a variant). x25519-dalek returns zeros
    ///   silently in that case rather than erroring; we treat as fatal.
    pub fn derive_shared_secret(self, peer_pub: &[u8; 32]) -> Result<SessionKey> {
        if is_low_order_x25519(peer_pub) {
            bail!("peer ephemeral pub is a known low-order / small-subgroup point");
        }
        let peer = PublicKey::from(*peer_pub);
        let raw: SharedSecret = self.secret.diffie_hellman(&peer);
        let raw_bytes = raw.as_bytes();
        if raw_bytes.iter().all(|b| *b == 0) {
            bail!("X25519 shared secret is all zeros — invalid peer_pub");
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(raw_bytes);
        // raw + our secret are dropped here.
        Ok(SessionKey(out))
    }
}

/// Known low-order / small-subgroup X25519 public keys per RFC 7748 §7.
/// Any peer sending one of these is either malformed or actively hostile;
/// derivation with them would produce a predictable shared secret.
fn is_low_order_x25519(pub_bytes: &[u8; 32]) -> bool {
    const LOW_ORDER: [[u8; 32]; 7] = [
        // 0
        [0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        // 1
        [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        // 325606250916557431795983626356110631294008115727848805560023387167927233504
        [0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
         0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00],
        // 39382357235489614581723060781553021112529911719440698176882885853963445705823
        [0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
         0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57],
        // p - 1
        [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
        // p
        [0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
        // p + 1
        [0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    ];
    LOW_ORDER.iter().any(|p| constant_time_eq(p, pub_bytes))
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 { diff |= a[i] ^ b[i]; }
    diff == 0
}

/// Raw X25519 shared secret S = X25519(local_priv, peer_pub). 32 bytes,
/// non-uniform distribution — never use directly as an AEAD key. Feed
/// through `wrap_key(session_id)` to get a proper symmetric key.
pub struct SessionKey(pub [u8; 32]);
impl Drop for SessionKey { fn drop(&mut self) { self.0.zeroize(); } }

impl SessionKey {
    /// Derive the AEAD wrap key from S with session_id as salt. Per Seb
    /// 2026-09-03: session_id is public, but binding the derivation to
    /// it guarantees the wrap key is specific to this exact session +
    /// this specific purpose ("transfer-v1 wrap-key" info string).
    pub fn wrap_key(&self, session_id: &[u8; 32]) -> WrapKey {
        let hkdf = Hkdf::<Sha256>::new(Some(session_id), &self.0);
        let mut out = [0u8; 32];
        hkdf.expand(b"transfer-v1 wrap-key", &mut out)
            .expect("32 bytes fits within HKDF-SHA256 output length");
        WrapKey(out)
    }

    /// Derive a DEDICATED meta-encryption key from S. Distinct from
    /// wrap_key and B so a break of any one key doesn't propagate to
    /// the others. Per Seb 2026-09-03: meta encryption must guard S + B
    /// even if the plaintext meta is known to the attacker — using a
    /// separate derived key (belt-and-suspenders beyond AEAD's own
    /// known-plaintext resistance) satisfies that.
    pub fn meta_key(&self, session_id: &[u8; 32]) -> MetaKey {
        let hkdf = Hkdf::<Sha256>::new(Some(session_id), &self.0);
        let mut out = [0u8; 32];
        hkdf.expand(b"transfer-v1 meta-key", &mut out)
            .expect("32 bytes fits within HKDF-SHA256 output length");
        MetaKey(out)
    }
}

/// Purpose-specific 32-byte AEAD key for encrypting the meta frame.
/// Derived from S with the "transfer-v1 meta-key" info string, so it's
/// distinct from both wrap_key (which encrypts B) and B (which encrypts
/// chunks). A break of any one key doesn't leak the others.
pub struct MetaKey(pub [u8; 32]);
impl Drop for MetaKey { fn drop(&mut self) { self.0.zeroize(); } }

impl MetaKey {
    /// Encrypt the meta JSON bytes with a fresh random nonce.
    /// AAD is bound to `session_id` so an attacker can't replay a meta
    /// frame from one session into another (even with the same URL A,
    /// session_ids match but wrap keys differ — this belts + suspenders
    /// prevents any cross-session mixing).
    pub fn encrypt_meta(&self, session_id: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, aes_gcm::aead::Payload { msg: plaintext, aad: session_id })
            .map_err(|e| anyhow!("encrypt_meta: {e}"))?;
        Ok((nonce.to_vec(), ct))
    }

    pub fn decrypt_meta(&self, session_id: &[u8; 32], nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 12 { bail!("meta nonce must be 12 bytes"); }
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0));
        cipher
            .decrypt(Nonce::from_slice(nonce), aes_gcm::aead::Payload { msg: ct, aad: session_id })
            .map_err(|e| anyhow!("decrypt_meta: {e}"))
    }

    /// Convenience: given a sender identity's Ed25519 signing key, sign
    /// SHA256(session_id || meta_nonce || meta_ct). Binds the signature
    /// to the exact session + exact ciphertext + nonce, so an attacker
    /// can't lift a signature from one meta into another session or
    /// re-sign a mutated ciphertext.
    ///
    /// Receiver verifies by recomputing the same hash and calling
    /// ed25519's `verify_strict`. Signing is OPTIONAL — anonymous
    /// transfers work with no signature at all.
    pub fn meta_signing_hash(session_id: &[u8; 32], nonce: &[u8], ct: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(session_id);
        hasher.update(nonce);
        hasher.update(ct);
        hasher.finalize().into()
    }
}

/// Purpose-specific 32-byte AEAD key derived from S + session_id.
pub struct WrapKey(pub [u8; 32]);
impl Drop for WrapKey { fn drop(&mut self) { self.0.zeroize(); } }

impl WrapKey {
    /// AEAD-wrap the sender's freshly-generated bulk key B under this
    /// wrap key. Returns (nonce, ciphertext) — both need to be sent on
    /// the wire.
    pub fn wrap_bulk_key(&self, bulk: &BulkKey) -> Result<(Vec<u8>, Vec<u8>)> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, bulk.0.as_slice())
            .map_err(|e| anyhow!("wrap_bulk_key: {e}"))?;
        Ok((nonce.to_vec(), ct))
    }

    /// Unwrap the sender-provided ciphertext to recover B.
    pub fn unwrap_bulk_key(&self, nonce: &[u8], ct: &[u8]) -> Result<BulkKey> {
        if nonce.len() != 12 { bail!("nonce must be 12 bytes"); }
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0));
        let pt = cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|e| anyhow!("unwrap_bulk_key: {e}"))?;
        if pt.len() != 32 { bail!("unwrapped B length {} ≠ 32", pt.len()); }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&pt);
        Ok(BulkKey(buf))
    }
}

/// Bulk stream key B. Fresh per transfer, wiped on drop.
#[derive(Clone)]
pub struct BulkKey(pub [u8; 32]);
impl Drop for BulkKey { fn drop(&mut self) { self.0.zeroize(); } }

impl BulkKey {
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        Self(buf)
    }

    /// Deterministic 12-byte nonce from chunk index. Little-endian u64
    /// in the low 8 bytes, high 4 bytes zero — max 2^64 chunks per key,
    /// which at 1 MiB relay chunks is 16 exabytes, well past any real
    /// transfer size.
    fn chunk_nonce(idx: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&idx.to_le_bytes());
        n
    }

    pub fn encrypt_chunk(&self, idx: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0));
        let nonce = Self::chunk_nonce(idx);
        cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|e| anyhow!("encrypt_chunk {idx}: {e}"))
    }

    pub fn decrypt_chunk(&self, idx: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0));
        let nonce = Self::chunk_nonce(idx);
        cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|e| anyhow!("decrypt_chunk {idx}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let share = ShareKey::random();
        let session_id_bytes: [u8; 32] = {
            let mut buf = [0u8; 32];
            for (i, byte) in share.session_id_hex().as_bytes().chunks(2).enumerate() {
                let s = std::str::from_utf8(byte).unwrap();
                buf[i] = u8::from_str_radix(s, 16).unwrap();
            }
            buf
        };
        let s = SessionKey({
            let mut b = [0u8; 32]; OsRng.fill_bytes(&mut b); b
        });
        let wk = s.wrap_key(&session_id_bytes);
        let b = BulkKey::random();
        let orig = b.0;
        let (nonce, ct) = wk.wrap_bulk_key(&b).unwrap();
        let unwrapped = wk.unwrap_bulk_key(&nonce, &ct).unwrap();
        assert_eq!(unwrapped.0, orig);
    }

    #[test]
    fn chunk_roundtrip() {
        let b = BulkKey::random();
        let pt = b"the quick brown fox jumps over the lazy dog";
        for idx in [0u64, 1, 42, u32::MAX as u64, u64::MAX / 2] {
            let ct = b.encrypt_chunk(idx, pt).unwrap();
            let dec = b.decrypt_chunk(idx, &ct).unwrap();
            assert_eq!(dec, pt);
            // wrong index must fail (authenticated encryption)
            let wrong = b.decrypt_chunk(idx.wrapping_add(1), &ct);
            assert!(wrong.is_err());
        }
    }

    #[test]
    fn ephemeral_kex_derives_matching_keys() {
        let alice = Ephemeral::generate();
        let bob = Ephemeral::generate();
        let alice_pub = alice.public_bytes();
        let bob_pub = bob.public_bytes();
        let alice_s = alice.derive_shared_secret(&bob_pub).unwrap();
        let bob_s = bob.derive_shared_secret(&alice_pub).unwrap();
        assert_eq!(alice_s.0, bob_s.0);
    }

    #[test]
    fn mac_binds_ephemeral_to_share_key() {
        let a1 = ShareKey::random();
        let a2 = ShareKey::random();
        let eph = Ephemeral::generate().public_bytes();
        assert_ne!(a1.mac_ephemeral_pub(&eph), a2.mac_ephemeral_pub(&eph));
    }

    #[test]
    fn session_id_is_deterministic_hash_of_a() {
        let a = ShareKey::random();
        let sid1 = a.session_id_hex();
        let sid2 = a.session_id_hex();
        assert_eq!(sid1, sid2);
        assert_eq!(sid1.len(), 64);
    }

    #[test]
    fn data_commitment_roundtrip() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let key = BulkKey::random();
        let sk = ShareKey::from_data_commitment(data, &key);
        assert!(sk.verify_data_commitment(data, &key));
        // tampering data breaks verification
        let tampered = b"the quick brown fox jumps over the LAZY dog";
        assert!(!sk.verify_data_commitment(tampered, &key));
        // wrong key also breaks
        let wrong_key = BulkKey::random();
        assert!(!sk.verify_data_commitment(data, &wrong_key));
    }

    #[test]
    fn share_key_hex_roundtrip() {
        let a = ShareKey::random();
        let hex = a.to_hex();
        let a2 = ShareKey::from_hex(&hex).unwrap();
        assert_eq!(a.0, a2.0);
    }

    #[test]
    fn meta_encrypt_decrypt_roundtrip_binds_session() {
        let s = SessionKey({ let mut b = [0u8; 32]; OsRng.fill_bytes(&mut b); b });
        let session_id_a = { let mut b = [0u8; 32]; OsRng.fill_bytes(&mut b); b };
        let session_id_b = { let mut b = [0u8; 32]; OsRng.fill_bytes(&mut b); b };
        let mk = s.meta_key(&session_id_a);
        let plaintext = br#"{"type":"meta","name":"file.bin","size":42}"#;
        let (nonce, ct) = mk.encrypt_meta(&session_id_a, plaintext).unwrap();
        // correct session_id decrypts
        let pt = mk.decrypt_meta(&session_id_a, &nonce, &ct).unwrap();
        assert_eq!(pt, plaintext);
        // wrong session_id in AAD fails
        assert!(mk.decrypt_meta(&session_id_b, &nonce, &ct).is_err());
    }

    #[test]
    fn wrap_and_meta_keys_are_distinct() {
        let s = SessionKey({ let mut b = [0u8; 32]; OsRng.fill_bytes(&mut b); b });
        let sid = { let mut b = [0u8; 32]; OsRng.fill_bytes(&mut b); b };
        let w = s.wrap_key(&sid);
        let m = s.meta_key(&sid);
        assert_ne!(w.0, m.0);
    }

    #[test]
    fn share_link_b64_roundtrip() {
        let sk = ShareKey::random();
        let sig = { let mut b = [0u8; 32]; OsRng.fill_bytes(&mut b); b };
        let link = ShareLink::new(sk.clone(), sig);
        let s = link.to_b64_url();
        assert_eq!(s.len(), 86); // base64url-no-pad of 64 bytes
        let link2 = ShareLink::from_b64_url(&s).unwrap();
        assert_eq!(link2.share_key.0, sk.0);
        assert_eq!(link2.signature, sig);
    }

    #[test]
    fn share_link_bad_length_rejects() {
        // 63 raw bytes → decodes but wrong length
        let short = "A".repeat(84);
        assert!(ShareLink::from_b64_url(&short).is_err());
        // garbage
        assert!(ShareLink::from_b64_url("!!!").is_err());
    }

    #[test]
    fn commitment_hasher_matches_one_shot_and_verify() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let key = BulkKey::random();
        // one-shot via existing helper
        let one_shot = ShareKey::from_data_commitment(data, &key);
        // streaming
        let mut h = CommitmentHasher::new();
        h.update(&data[..10]);
        h.update(&data[10..25]);
        h.update(&data[25..]);
        let sig = h.finalize(&key);
        assert_eq!(sig, one_shot.0);
        // and ShareLink::verify_signature agrees
        let link = ShareLink::new(ShareKey::random(), sig);
        assert!(link.verify_signature(data, &key));
        // tampered data fails
        let tampered = b"the quick brown fox jumps over the LAZY dog";
        assert!(!link.verify_signature(tampered, &key));
        // wrong key fails
        let wrong = BulkKey::random();
        assert!(!link.verify_signature(data, &wrong));
    }
}
