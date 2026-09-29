use std::marker::PhantomData;

use crate::{Error};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Two-layer crypto model:
/// - K_session: transport encryption. Derived from ECDH between peers via signaling.
///   Session key is ephemeral; the server relay only ever sees ciphertext under K_session.
/// - K_content: payload encryption. Derived from an optional receiver password via Argon2id.
///   Wraps the file payload BEFORE it enters transport, so even a compromised relay
///   holding buffered ciphertext cannot decrypt without the password.

pub struct SessionKey(pub [u8; 32]);
pub struct ContentKey(pub [u8; 32]);
#[derive(Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);
#[derive(Serialize, Deserialize)]
pub struct SessionMac(pub [u8; 32]);
pub struct WrappedContentKey(pub Vec<u8>);

impl From<x25519_dalek::PublicKey> for PublicKey {
    fn from(value: x25519_dalek::PublicKey) -> Self {
        PublicKey(value.to_bytes())
    }
}
impl Into<x25519_dalek::PublicKey> for PublicKey {
    fn into(self) -> x25519_dalek::PublicKey {
        x25519_dalek::PublicKey::from(self.0)
    }
}

/// X25519 key exchange for peer→peer session key agreement via signaling.
pub struct KeyExchange {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

impl KeyExchange {
    pub fn new() -> Self {
        let secret = x25519_dalek::StaticSecret::random_from_rng(&mut rand_core::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Derive K_session from the peer's public key. HKDF-SHA256 over the ECDH output.
    pub fn derive_session_key(&self, peer_public: &[u8; 32], session_id: &str) -> SessionKey {
        let peer = x25519_dalek::PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer);
        let hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"bitmule/v1/session-key", &mut key)
            .expect("hkdf expand");
        SessionKey(key)
    }
}

impl SessionKey {
    pub fn encrypt_chunk(&self, nonce: &[u8; 24], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = XChaCha20Poly1305::new(self.0.as_slice().into());
        cipher
            .encrypt(XNonce::from_slice(nonce), plaintext)
            .map_err(|e| Error::Crypto(format!("encrypt: {e}")))
    }

    pub fn decrypt_chunk(&self, nonce: &[u8; 24], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = XChaCha20Poly1305::new(self.0.as_slice().into());
        cipher
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .map_err(|e| Error::Crypto(format!("decrypt: {e}")))
    }
}
