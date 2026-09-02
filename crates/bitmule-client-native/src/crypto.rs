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
use chacha20poly1305::{aead::Aead, AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce};
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
}

/// Purpose-specific 32-byte AEAD key derived from S + session_id.
pub struct WrapKey(pub [u8; 32]);
impl Drop for WrapKey { fn drop(&mut self) { self.0.zeroize(); } }

impl WrapKey {
    /// AEAD-wrap the sender's freshly-generated bulk key B under this
    /// wrap key. Returns (nonce, ciphertext) — both need to be sent on
    /// the wire.
    pub fn wrap_bulk_key(&self, bulk: &BulkKey) -> Result<(Vec<u8>, Vec<u8>)> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.0));
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, bulk.0.as_slice())
            .map_err(|e| anyhow!("wrap_bulk_key: {e}"))?;
        Ok((nonce.to_vec(), ct))
    }

    /// Unwrap the sender-provided ciphertext to recover B.
    pub fn unwrap_bulk_key(&self, nonce: &[u8], ct: &[u8]) -> Result<BulkKey> {
        if nonce.len() != 12 { bail!("nonce must be 12 bytes"); }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.0));
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
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.0));
        let nonce = Self::chunk_nonce(idx);
        cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|e| anyhow!("encrypt_chunk {idx}: {e}"))
    }

    pub fn decrypt_chunk(&self, idx: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.0));
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
    fn share_key_hex_roundtrip() {
        let a = ShareKey::random();
        let hex = a.to_hex();
        let a2 = ShareKey::from_hex(&hex).unwrap();
        assert_eq!(a.0, a2.0);
    }
}
