use x25519_dalek::{PublicKey, StaticSecret, SharedSecret};
use hkdf::Hkdf;
use sha2::Sha256;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead};
use aes_gcm::aead::{Aead, Payload};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;
use serde::{Serialize, de::DeserializeOwned};
use std::marker::PhantomData;

use crate::SessionId;

fn concat_arrays<const N: usize, const M: usize>(a: &[u8; N], b: &[u8; M]) -> [u8; N + M] {
    let mut res = [0u8; N + M];
    let (left, right) = res.split_at_mut(N);
    left.copy_from_slice(a);
    right.copy_from_slice(b);
    res
}

pub enum Error {
    Serde(postcard::Error),
    Crypto(aead::Error),
    Counter,
}

pub enum OuterKeyKind {}
pub enum InnerKeyKind {}

pub struct Envelope<KeyKind, T> {
    _k: PhantomData<KeyKind>,
    _m: PhantomData<T>,
    counter: u32,
    nonce: [u8; 12], // EAED
    data: Vec<u8>,
}


/// Peer static identity: X25519 keypair.
pub struct IdentityKeypair {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl IdentityKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Derive the outer_key shared with `peer_pub` under this session.
    /// outer_key = HKDF-SHA256(
    ///     salt = session_id,
    ///     ikm  = ECDH(local_priv, peer_pub),
    ///     info = b"bitmule-p2p outer-key v1",
    /// )
    /// Same-peer + same-session = same outer_key on both sides
    /// (X25519-DH is commutative). Session_id in salt binds the key to
    /// this specific session, so leaking one session's outer_key doesn't
    /// leak another between the same two peers.
    pub fn outer_key_for(&self, peer_pub: &PublicKey, session_id: &SessionId) -> OuterKey {
        let shared: SharedSecret = self.secret.diffie_hellman(peer_pub);
        let hkdf = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared.as_bytes());
        let mut key = [0u8; 32];
        hkdf.expand(b"bitmule-p2p outer-key v1", &mut key)
            .expect("32 bytes fits within HKDF-SHA256 output length");
        OuterKey(key)
    }
}

pub struct OuterKey(pub [u8; 32]);
impl Drop for OuterKey {
    fn drop(&mut self) { self.0.zeroize(); }
}

#[derive(Default)]
pub struct EnvelopeCounter {
    inner: u32,
}
impl EnvelopeCounter {
    fn as_bytes(&self) -> [u8; 4] {
        self.inner.to_le_bytes()
    }
    fn increment(&mut self) {
        self.inner += 1;
    }
}

impl<T: Serialize + DeserializeOwned> Envelope<OuterKeyKind, T> {
    /// Seal `payload` under `key` with a fresh random nonce.
    /// `counter` should be monotonic per-key; caller tracks last-seen on
    /// the receive side and rejects non-monotonic envelopes as replays.
    /// AAD binds session_id + counter so an attacker can't replay the
    /// ciphertext into a different session or reorder in-session.
    pub fn seal(
        payload: &T,
        key: &OuterKey,
        counter: &mut EnvelopeCounter,
        session_id: &SessionId,
    ) -> Result<Self, Error> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = postcard::to_stdvec(payload)
            .map_err(Error::Serde)?;

        let aad = concat_arrays(session_id.as_bytes(), &counter.as_bytes());

        let ct = cipher.encrypt(nonce, Payload { msg: &plaintext, aad: &aad })
            .map_err(Error::Crypto)?;

        counter.increment();

        Ok(Envelope {
            _k: PhantomData,
            _m: PhantomData,
            counter: counter.inner,
            nonce: nonce_bytes,
            data: ct,
        })
    }

    /// Verify + decrypt. Returns the inner T. Caller MUST additionally
    /// enforce `envelope.counter > last_seen_counter` before treating T
    /// as fresh — AEAD auth alone doesn't stop replay of a valid old
    /// message, only forgery of a new one.
    pub fn open(
        &self,
        key: &OuterKey,
        session_id: &SessionId,
        counter: &mut EnvelopeCounter,
    ) -> Result<T, Error> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
        let nonce = Nonce::from_slice(&self.nonce);

        let aad = concat_arrays(session_id.as_bytes(), &self.counter.to_le_bytes());

        let plaintext = cipher.decrypt(nonce, Payload { msg: &self.data, aad: &aad })
            .map_err(Error::Crypto)?;

        counter.increment();

        if counter.inner != self.counter {
            return Err(Error::Counter);
        }

        postcard::from_bytes(&plaintext)
            .map_err(Error::Serde)
    }
}


/// Post-X3DH shared session key. Derived from three DH operations over the
/// initiator's + responder's static identity keys and their per-session
/// ephemerals (see [`derive_session_key`]). Provides forward secrecy: even
/// if a peer's static private key leaks later, past traffic under this
/// session_key stays confidential — decryption requires the ephemeral
/// privates too, which are zeroized after derivation.
pub struct SessionKey(pub [u8; 32]);
impl Drop for SessionKey {
    fn drop(&mut self) { self.0.zeroize(); }
}


/// Ephemeral X25519 keypair used for the X3DH exchange.
///
/// Uses `StaticSecret` under the hood (not `EphemeralSecret`) because X3DH
/// requires the ephemeral private to be used in TWO DH ops (`dh2` and
/// `dh3`), which `EphemeralSecret` can't support since it's consumed by a
/// single `diffie_hellman()` call. `Zeroize` on drop keeps the same
/// forward-secrecy story — the private key is destroyed once the session
/// key has been derived.
pub struct EphemeralKeypair {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}


/// Derive the post-X3DH session_key from this peer's static + ephemeral
/// privates and the counterpart's static + ephemeral pubs.
///
/// Standard X3DH (Signal-shape, minus the async prekey machinery since
/// bitmule peers are synchronous — both online during KEX):
/// ```text
///   DH1 = DH(IK_A_priv, EK_B_pub)   # A's identity × B's ephemeral
///   DH2 = DH(EK_A_priv, IK_B_pub)   # A's ephemeral × B's identity
///   DH3 = DH(EK_A_priv, EK_B_pub)   # A's ephemeral × B's ephemeral
///   session_key = HKDF-SHA256(
///       salt = session_id,
///       ikm  = DH1 || DH2 || DH3,
///       info = b"bitmule-p2p session-key v1" || IK_A_pub || IK_B_pub,
///   )
/// ```
///
/// Both peers compute the same session_key because X25519-DH is symmetric
/// (DH(x, gy) == DH(y, gx)). To agree on the AD binding (IK_A||IK_B) both
/// sides need to agree who "A" is — we canonicalise by lex-comparing the
/// two identity pubs: the smaller-bytes IK is "A", the larger is "B". This
/// avoids either peer needing a role bit passed in.
///
/// The AD binding of IK_A_pub||IK_B_pub is X3DH's identity-key-substitution
/// defence — an attacker can't swap in different IKs while reusing captured
/// ephemerals without invalidating the derived key.
pub fn derive_session_key(
    my_ik: &IdentityKeypair,
    my_ek: &EphemeralKeypair,
    peer_ik_pub: &PublicKey,
    peer_ek_pub: &PublicKey,
    session_id: &SessionId,
) -> SessionKey {
    // Canonical role: lower-bytes IK_pub is initiator ("A"), higher is
    // responder ("B"). Same order on both sides regardless of who actually
    // sent Init vs Response on the wire.
    let am_initiator = my_ik.public.as_bytes() < peer_ik_pub.as_bytes();
    let (ik_a_pub, ik_b_pub) = if am_initiator {
        (&my_ik.public, peer_ik_pub)
    } else {
        (peer_ik_pub, &my_ik.public)
    };

    // Compute the three DHs from our side. Both sides get bit-identical
    // results because X25519 DH is symmetric.
    let dh1: [u8; 32] = if am_initiator {
        // I'm A. DH1 = DH(IK_A_priv, EK_B_pub) = my_ik_priv × peer_ek_pub
        my_ik.secret.diffie_hellman(peer_ek_pub).to_bytes()
    } else {
        // I'm B. DH1 conceptually = DH(IK_A_priv, EK_B_pub) — I have IK_B_priv + EK_B_priv.
        // By symmetry, DH(IK_A_priv, EK_B_pub) = DH(EK_B_priv, IK_A_pub).
        my_ek.secret.diffie_hellman(peer_ik_pub).to_bytes()
    };
    let dh2: [u8; 32] = if am_initiator {
        // I'm A. DH2 = DH(EK_A_priv, IK_B_pub) = my_ek_priv × peer_ik_pub
        my_ek.secret.diffie_hellman(peer_ik_pub).to_bytes()
    } else {
        // I'm B. DH2 conceptually = DH(EK_A_priv, IK_B_pub) — I have IK_B_priv.
        // By symmetry, DH(EK_A_priv, IK_B_pub) = DH(IK_B_priv, EK_A_pub).
        my_ik.secret.diffie_hellman(peer_ek_pub).to_bytes()
    };
    // DH3 is symmetric on both sides: DH(EK_A_priv, EK_B_pub) = DH(EK_B_priv, EK_A_pub)
    let dh3: [u8; 32] = my_ek.secret.diffie_hellman(peer_ek_pub).to_bytes();

    let mut ikm = [0u8; 96];
    ikm[0..32].copy_from_slice(&dh1);
    ikm[32..64].copy_from_slice(&dh2);
    ikm[64..96].copy_from_slice(&dh3);

    let mut info = Vec::with_capacity(26 + 32 + 32);
    info.extend_from_slice(b"bitmule-p2p session-key v1");
    info.extend_from_slice(ik_a_pub.as_bytes());
    info.extend_from_slice(ik_b_pub.as_bytes());

    let hkdf = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), &ikm);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .expect("32 bytes fits within HKDF-SHA256 output length");
    SessionKey(key)
}


impl<T: Serialize + DeserializeOwned> Envelope<InnerKeyKind, T> {
    /// Seal `payload` under the post-X3DH `session_key`. Same on-wire
    /// envelope shape as the outer variant (counter + nonce + ct); only
    /// the key at the seal/open call site differs. Phantom KeyKind
    /// prevents accidentally opening an inner envelope with an outer key
    /// or vice versa at compile time.
    pub fn seal(
        payload: &T,
        key: &SessionKey,
        counter: &mut EnvelopeCounter,
        session_id: &SessionId,
    ) -> Result<Self, Error> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = postcard::to_stdvec(payload)
            .map_err(Error::Serde)?;

        let aad = concat_arrays(session_id.as_bytes(), &counter.as_bytes());

        let ct = cipher.encrypt(nonce, Payload { msg: &plaintext, aad: &aad })
            .map_err(Error::Crypto)?;

        counter.increment();

        Ok(Envelope {
            _k: PhantomData,
            _m: PhantomData,
            counter: counter.inner,
            nonce: nonce_bytes,
            data: ct,
        })
    }

    /// Verify + decrypt an inner envelope. Matches the outer variant's
    /// contract: caller supplies the same monotonic counter as the peer,
    /// mismatch returns `Error::Counter` (out-of-order or replay).
    pub fn open(
        &self,
        key: &SessionKey,
        session_id: &SessionId,
        counter: &mut EnvelopeCounter,
    ) -> Result<T, Error> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
        let nonce = Nonce::from_slice(&self.nonce);

        let aad = concat_arrays(session_id.as_bytes(), &self.counter.to_le_bytes());

        let plaintext = cipher.decrypt(nonce, Payload { msg: &self.data, aad: &aad })
            .map_err(Error::Crypto)?;

        counter.increment();

        if counter.inner != self.counter {
            return Err(Error::Counter);
        }

        postcard::from_bytes(&plaintext)
            .map_err(Error::Serde)
    }
}
