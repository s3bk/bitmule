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


pub struct Envelope<T> {
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

impl<T: Serialize + DeserializeOwned> Envelope<T> {
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
