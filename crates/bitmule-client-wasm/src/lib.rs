//! Browser-side bitmule client. Compiled to wasm and loaded by the
//! landing-page SPA under `web/`.
//!
//! Exposes:
//!   - `version()` / `random_session_id_hex()` — SPA smoke test.
//!   - `ShareKey`, `ShareLink` — URL secret + share-link handling.
//!   - `Ephemeral`, `WrapKey`, `MetaKey`, `BulkKey` — KEX + AEAD
//!     primitives the SPA needs to talk to the modern (AEAD) wire.
//!
//! Everything crypto-related is a thin `#[wasm_bindgen]` wrapper over
//! the shared `bitmule-crypto` crate — same code the native CLI uses,
//! bit-for-bit identical outputs.

use bitmule_core::SessionId;
use bitmule_crypto as bx;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Fresh 32-byte session id, hex-encoded. The SPA uses this to open a
/// signaling socket at `/ws/<hex>` on the server.
#[wasm_bindgen]
pub fn random_session_id_hex() -> String {
    SessionId::random().as_hex()
}

// ---- ShareKey (URL secret A) -----------------------------------------

#[wasm_bindgen]
pub struct ShareKey(bx::ShareKey);

#[wasm_bindgen]
impl ShareKey {
    /// Mint a fresh random 32-byte URL secret.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(bx::ShareKey::random())
    }

    /// Parse from lowercase 64-char hex.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(s: &str) -> Result<ShareKey, JsError> {
        bx::ShareKey::from_hex(s)
            .map(Self)
            .map_err(|e| JsError::new(&format!("{e}")))
    }

    /// Lowercase 64-char hex.
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// `SHA256(A)` hex — the public session id the server sees.
    #[wasm_bindgen(js_name = sessionIdHex)]
    pub fn session_id_hex(&self) -> String {
        self.0.session_id_hex()
    }

    /// HMAC-SHA256(A, ephemeral_pub). The other side verifies this
    /// against its own MAC on our ephemeral pub during KEX so a MITM
    /// without A can't inject a spoofed key.
    #[wasm_bindgen(js_name = macEphemeralPub)]
    pub fn mac_ephemeral_pub(&self, pub_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
        let arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| JsError::new("mac_ephemeral_pub: pub_bytes must be 32 bytes"))?;
        Ok(self.0.mac_ephemeral_pub(&arr).to_vec())
    }
}

// ---- ShareLink (share_key + signature) ------------------------------

#[wasm_bindgen]
pub struct ShareLink(bx::ShareLink);

#[wasm_bindgen]
impl ShareLink {
    /// Parse an 86-char base64url share fragment.
    #[wasm_bindgen(js_name = fromB64Url)]
    pub fn from_b64_url(s: &str) -> Result<ShareLink, JsError> {
        bx::ShareLink::from_b64_url(s)
            .map(Self)
            .map_err(|e| JsError::new(&format!("{e}")))
    }

    /// Encode as base64url (URL fragment form).
    #[wasm_bindgen(js_name = toB64Url)]
    pub fn to_b64_url(&self) -> String {
        self.0.to_b64_url()
    }

    /// Extract the embedded ShareKey (moves — link cannot be reused).
    #[wasm_bindgen(js_name = takeShareKey)]
    pub fn take_share_key(self) -> ShareKey {
        ShareKey(self.0.share_key)
    }

    /// URL-committed SHA256(data || bulk_key). 32 bytes.
    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.0.signature.to_vec()
    }
}

// ---- Ephemeral X25519 ------------------------------------------------

/// Ephemeral X25519 keypair. Generate one per session, publish
/// `publicBytes`, receive the peer's public bytes, then call
/// `deriveSharedSecret` (which consumes self so the ephemeral private
/// zeroizes after derivation).
#[wasm_bindgen]
pub struct Ephemeral(Option<bx::Ephemeral>);

#[wasm_bindgen]
impl Ephemeral {
    #[wasm_bindgen(constructor)]
    pub fn generate() -> Self {
        Self(Some(bx::Ephemeral::generate()))
    }

    /// 32-byte X25519 public key. Send this to the peer over WS.
    #[wasm_bindgen(js_name = publicBytes)]
    pub fn public_bytes(&self) -> Result<Vec<u8>, JsError> {
        let inner = self
            .0
            .as_ref()
            .ok_or_else(|| JsError::new("Ephemeral already consumed"))?;
        Ok(inner.public_keypublic_key().to_vec())
    }

    /// Derive the shared secret with the peer's public bytes. Consumes
    /// self — the ephemeral private is zeroized. Returns `SessionKey`
    /// from which wrap_key + meta_key are derived.
    #[wasm_bindgen(js_name = deriveSharedSecret)]
    pub fn derive_shared_secret(mut self, peer_pub: &[u8]) -> Result<SessionKey, JsError> {
        let arr: [u8; 32] = peer_pub
            .try_into()
            .map_err(|_| JsError::new("peer_pub must be 32 bytes"))?;
        let eph = self
            .0
            .take()
            .ok_or_else(|| JsError::new("Ephemeral already consumed"))?;
        eph.derive_shared_secret(&arr)
            .map(SessionKey)
            .map_err(|e| JsError::new(&format!("{e}")))
    }
}

// ---- SessionKey (S = X25519(local_priv, peer_pub)) -----------------

#[wasm_bindgen]
pub struct SessionKey(bx::SessionKey);

#[wasm_bindgen]
impl SessionKey {
    /// HKDF-derive the AEAD wrap_key. `session_id` is the 32-byte
    /// hex-decoded session id used as salt.
    #[wasm_bindgen(js_name = wrapKey)]
    pub fn wrap_key(&self, session_id: &[u8]) -> Result<WrapKey, JsError> {
        let arr: [u8; 32] = session_id
            .try_into()
            .map_err(|_| JsError::new("session_id must be 32 bytes"))?;
        Ok(WrapKey(self.0.wrap_key(&arr)))
    }

    /// HKDF-derive the AEAD meta_key.
    #[wasm_bindgen(js_name = metaKey)]
    pub fn meta_key(&self, session_id: &[u8]) -> Result<MetaKey, JsError> {
        let arr: [u8; 32] = session_id
            .try_into()
            .map_err(|_| JsError::new("session_id must be 32 bytes"))?;
        Ok(MetaKey(self.0.meta_key(&arr)))
    }
}

// ---- WrapKey ---------------------------------------------------------

#[wasm_bindgen]
pub struct WrapKey(bx::WrapKey);

/// Result of `wrap`/`encrypt` operations — 12-byte nonce + ciphertext.
/// Both fields land on the wire as hex.
#[wasm_bindgen]
pub struct AeadOut {
    nonce: Vec<u8>,
    ct: Vec<u8>,
}

#[wasm_bindgen]
impl AeadOut {
    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn ct(&self) -> Vec<u8> {
        self.ct.clone()
    }
}

#[wasm_bindgen]
impl WrapKey {
    /// AEAD-wrap a `BulkKey` under this session's wrap_key. Sender
    /// calls this before sending KeyWrap over WS.
    #[wasm_bindgen(js_name = wrapBulkKey)]
    pub fn wrap_bulk_key(&self, bulk: &BulkKey) -> Result<AeadOut, JsError> {
        let (nonce, ct) = self
            .0
            .wrap_bulk_key(&bulk.0)
            .map_err(|e| JsError::new(&format!("{e}")))?;
        Ok(AeadOut { nonce, ct })
    }

    /// Receiver-side: unwrap a KeyWrap payload into a `BulkKey`.
    #[wasm_bindgen(js_name = unwrapBulkKey)]
    pub fn unwrap_bulk_key(&self, nonce: &[u8], ct: &[u8]) -> Result<BulkKey, JsError> {
        self.0
            .unwrap_bulk_key(nonce, ct)
            .map(BulkKey)
            .map_err(|e| JsError::new(&format!("{e}")))
    }
}

// ---- MetaKey (encrypts the meta text frame) --------------------------

#[wasm_bindgen]
pub struct MetaKey(bx::MetaKey);

#[wasm_bindgen]
impl MetaKey {
    /// AEAD-encrypt the meta_plain bytes with session_id as AAD.
    #[wasm_bindgen(js_name = encryptMeta)]
    pub fn encrypt_meta(&self, session_id: &[u8], plaintext: &[u8]) -> Result<AeadOut, JsError> {
        let arr: [u8; 32] = session_id
            .try_into()
            .map_err(|_| JsError::new("session_id must be 32 bytes"))?;
        let (nonce, ct) = self
            .0
            .encrypt_meta(&arr, plaintext)
            .map_err(|e| JsError::new(&format!("{e}")))?;
        Ok(AeadOut { nonce, ct })
    }

    /// AEAD-decrypt a meta_enc payload.
    #[wasm_bindgen(js_name = decryptMeta)]
    pub fn decrypt_meta(
        &self,
        session_id: &[u8],
        nonce: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let arr: [u8; 32] = session_id
            .try_into()
            .map_err(|_| JsError::new("session_id must be 32 bytes"))?;
        self.0
            .decrypt_meta(&arr, nonce, ct)
            .map_err(|e| JsError::new(&format!("{e}")))
    }
}

// ---- BulkKey (per-chunk AEAD) ---------------------------------------

#[wasm_bindgen]
pub struct BulkKey(bx::BulkKey);

#[wasm_bindgen]
impl BulkKey {
    /// Mint a fresh random 32-byte bulk key. Sender-of-file calls
    /// this once before minting the share URL.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(bx::BulkKey::random())
    }

    /// AEAD-encrypt one chunk. Nonce is derived deterministically from
    /// `idx` (chunk index); receiver reconstructs the same nonce by
    /// counting chunks in order.
    #[wasm_bindgen(js_name = encryptChunk)]
    pub fn encrypt_chunk(&self, idx: u64, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        self.0
            .encrypt_chunk(idx, plaintext)
            .map_err(|e| JsError::new(&format!("{e}")))
    }

    /// AEAD-decrypt one chunk.
    #[wasm_bindgen(js_name = decryptChunk)]
    pub fn decrypt_chunk(&self, idx: u64, ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
        self.0
            .decrypt_chunk(idx, ciphertext)
            .map_err(|e| JsError::new(&format!("{e}")))
    }
}

// ---- Commitment hashing (URL signature) -----------------------------

/// Streaming SHA-256 with a `finalize(bulkKey)` step that yields the
/// URL signature (32 bytes). Sender-side only; receivers verify via
/// `ShareLink::verifySignature` on the assembled plaintext.
#[wasm_bindgen]
pub struct CommitmentHasher(bx::CommitmentHasher);

#[wasm_bindgen]
impl CommitmentHasher {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(bx::CommitmentHasher::new())
    }

    pub fn update(&mut self, chunk: &[u8]) {
        self.0.update(chunk);
    }

    pub fn finalize(self, bulk_key: &BulkKey) -> Vec<u8> {
        self.0.finalize(&bulk_key.0).to_vec()
    }
}
