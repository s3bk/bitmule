//! Browser-side bitmule client. Compiled to wasm and loaded by the SPA under
//! `web/`.
//!
//! The protocol lives here, in the same Rust the native client uses (message
//! formats, sealed envelopes, key exchange, fountain codes, proof of work);
//! the page only does I/O: the websocket, the relay's HTTP streams, and
//! WebRTC. Nothing in this crate touches the network.
//!
//! - [`Session`]: one session on the signaling server. Bytes from the
//!   websocket go in (`onServer`), events come out; `send` seals a message to
//!   a peer.
//! - [`Transfer`]: the sender's data: bulk key, commitment, relay encoding.
//! - [`RelayDecoder`], [`Verifier`]: the receiver's decoding and check.
//!
//! Messages to and from peers are plain JS objects with a `type` field, see
//! `message_to_js` / `message_from_js`.

mod data;
mod session;

use bitmule_core::{
    ReceiverId,
    pow,
    protocol::websocket::{Peer2Peer, PeerCaps, SdpAnswer, SdpOffer, UdpHello},
};
use bitmule_crypto as bx;
use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;

use session::{Core, Event};

#[wasm_bindgen(js_namespace = console, js_name = error)]
extern "C" {
    fn console_error(message: &str);
}

/// Panics go to the console with their message, not as a bare `unreachable`.
#[wasm_bindgen(start)]
pub fn start() {
    std::panic::set_hook(Box::new(|info| console_error(&format!("bitmule wasm panic: {info}"))));
}

/// Decompress a zstd frame (the entries of zips the CLI makes).
#[wasm_bindgen(js_name = zstdDecompress)]
pub fn zstd_decompress(data: &[u8]) -> Result<Vec<u8>, JsError> {
    data::zstd_decompress(data).map_err(js_err)
}

#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Capability bits for `Session`: what this client can do.
#[wasm_bindgen(js_name = CAP_RELAY)]
pub fn cap_relay() -> u8 {
    PeerCaps::RELAY.bits()
}
#[wasm_bindgen(js_name = CAP_WEBRTC)]
pub fn cap_webrtc() -> u8 {
    PeerCaps::WEBRTC.bits()
}

fn js_err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn set(object: &Object, key: &str, value: impl Into<JsValue>) {
    Reflect::set(object, &key.into(), &value.into()).unwrap();
}

fn bytes(data: &[u8]) -> Uint8Array {
    Uint8Array::from(data)
}

fn peer_id(hex: &str) -> Result<ReceiverId, JsError> {
    ReceiverId::from_hex(hex).map_err(js_err)
}

fn array_32(data: &[u8], what: &str) -> Result<[u8; 32], JsError> {
    data.try_into().map_err(|_| JsError::new(&format!("{what} must be 32 bytes")))
}

// ---- share keys and links ---------------------------------------------

/// The URL secret. `sessionIdHex` is what the server sees of it.
#[wasm_bindgen]
pub struct ShareKey(bx::ShareKey);

#[wasm_bindgen]
impl ShareKey {
    /// Parse from lowercase 64-char hex.
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(s: &str) -> Result<ShareKey, JsError> {
        bx::ShareKey::from_hex(s).map(Self).map_err(js_err)
    }

    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// `SHA256(A)` hex, the public session id.
    #[wasm_bindgen(js_name = sessionIdHex)]
    pub fn session_id_hex(&self) -> String {
        self.0.session_id_hex()
    }
}

/// The share link of a transfer: key and signature (the commitment to the data).
#[wasm_bindgen]
pub struct ShareLink {
    key: bx::ShareKey,
    signature: [u8; 32],
}

#[wasm_bindgen]
impl ShareLink {
    /// Parse the base64url fragment of a share URL.
    #[wasm_bindgen(js_name = fromB64Url)]
    pub fn from_b64_url(s: &str) -> Result<ShareLink, JsError> {
        let link = bx::ShareLink::from_b64_url(s).map_err(js_err)?;
        Ok(ShareLink { key: bx::ShareKey(link.share_key.0), signature: link.signature })
    }

    #[wasm_bindgen(js_name = toB64Url)]
    pub fn to_b64_url(&self) -> String {
        bx::ShareLink::new(bx::ShareKey(self.key.0), self.signature).to_b64_url()
    }

    #[wasm_bindgen(js_name = shareKeyHex)]
    pub fn share_key_hex(&self) -> String {
        self.key.to_hex()
    }

    #[wasm_bindgen(js_name = sessionIdHex)]
    pub fn session_id_hex(&self) -> String {
        self.key.session_id_hex()
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.signature.to_vec()
    }
}

// ---- the sender's transfer --------------------------------------------

/// The data a sender sends. Feed the whole file through `update` to get the
/// signature (`finish`), then hand it to `Session.setTransfer`.
#[wasm_bindgen]
pub struct Transfer(data::Outgoing);

/// Plaintext bytes of one block: what a streaming sender cuts its data into.
#[wasm_bindgen(js_name = blockPlain)]
pub fn block_plain() -> u32 {
    bitmule_client_common::fountain::BLOCK_PLAIN as u32
}

#[wasm_bindgen]
impl Transfer {
    /// `kind` is "single" (the bytes are the file) or "zip" (the bytes are a zip of files).
    /// `name` is what the receiver saves it as.
    #[wasm_bindgen(constructor)]
    pub fn new(kind: &str, name: Option<String>) -> Result<Transfer, JsError> {
        let kind = match kind {
            "single" => data::Kind::Single,
            "zip" => data::Kind::Zip,
            other => return Err(JsError::new(&format!("unknown transfer kind {other:?}"))),
        };
        Ok(Transfer(data::Outgoing::new(kind, name)))
    }

    pub fn update(&mut self, chunk: &[u8]) -> Result<(), JsError> {
        self.0.update(chunk).map_err(js_err)
    }

    /// All data has been fed; returns the signature for the share link.
    pub fn finish(&mut self) -> Result<Vec<u8>, JsError> {
        self.0.finish().map(|s| s.to_vec()).map_err(js_err)
    }

    #[wasm_bindgen(getter)]
    pub fn size(&self) -> f64 {
        self.0.size() as f64
    }
}

// ---- a session --------------------------------------------------------

#[wasm_bindgen]
pub struct Session {
    core: Core,
    signature: Option<[u8; 32]>,
    transfer: Option<data::Outgoing>,
}

#[wasm_bindgen]
impl Session {
    /// A session of our own, under a fresh key. `caps` is an or of `CAP_*`.
    pub fn create(caps: u8) -> Session {
        Session { core: Core::create(PeerCaps::from_bits_truncate(caps)), signature: None, transfer: None }
    }

    /// The session behind the key `key_hex`. `signature`, if the link had one,
    /// is what the received data is checked against.
    pub fn join(key_hex: &str, signature: Option<Vec<u8>>, caps: u8) -> Result<Session, JsError> {
        let key = bx::ShareKey::from_hex(key_hex).map_err(js_err)?;
        let signature = signature.map(|s| array_32(&s, "signature")).transpose()?;
        Ok(Session { core: Core::join(key, PeerCaps::from_bits_truncate(caps)), signature, transfer: None })
    }

    #[wasm_bindgen(js_name = isCreator)]
    pub fn is_creator(&self) -> bool {
        self.core.role == session::Role::Creator
    }

    #[wasm_bindgen(js_name = shareKeyHex)]
    pub fn share_key_hex(&self) -> String {
        self.core.share_key().to_hex()
    }

    #[wasm_bindgen(js_name = sessionIdHex)]
    pub fn session_id_hex(&self) -> String {
        self.core.session_id().as_hex()
    }

    #[wasm_bindgen(js_name = ourIdHex)]
    pub fn our_id_hex(&self) -> String {
        self.core.our_id().as_hex()
    }

    /// Search the proof of work for `/ws/create`, `count` nonces from `start`.
    /// Returns the nonce if one is among them. Call in a loop, yielding to
    /// the page in between.
    #[wasm_bindgen(js_name = powStep)]
    pub fn pow_step(&self, magic: u32, difficulty: u8, start: f64, count: u32) -> Option<f64> {
        self.core.pow_step(magic, difficulty, start as u64, count).map(|n| n as f64)
    }

    /// The first message for the websocket (binary): create or join.
    pub fn hello(&self) -> Vec<u8> {
        self.core.hello()
    }

    /// Process a binary websocket message. Returns the events:
    /// `{kind: "out", bytes}` (write to the websocket), `created`, `joined`,
    /// `peerJoined`, `peerReady`, `message`, `peerLeft`, `peerFull`, `text`.
    #[wasm_bindgen(js_name = onServer)]
    pub fn on_server(&mut self, message: &[u8]) -> Result<Array, JsError> {
        let events = self.core.on_server(message).map_err(js_err)?;
        let out = Array::new();
        for event in events {
            out.push(&event_to_js(event));
        }
        Ok(out)
    }

    /// Seal a message for a peer; returns bytes for the websocket. Fails if
    /// the secure channel to the peer is not up yet (`peerReady`).
    pub fn send(&mut self, peer: &str, message: &JsValue) -> Result<Vec<u8>, JsError> {
        let message = match message_from_js(message)? {
            // the manifest is made from the transfer we hold
            Peer2Peer::Manifest(_) => {
                let transfer = self.transfer.as_ref().ok_or_else(|| JsError::new("no transfer set"))?;
                Peer2Peer::Manifest(transfer.manifest())
            }
            other => other,
        };
        self.core.seal(peer_id(peer)?, &message).map_err(js_err)
    }

    pub fn forget(&mut self, peer: &str) -> Result<(), JsError> {
        self.core.forget(peer_id(peer)?);
        Ok(())
    }

    // -- sender --

    /// The data to send. Must be finished. Consumes the transfer.
    #[wasm_bindgen(js_name = setTransfer)]
    pub fn set_transfer(&mut self, transfer: Transfer) -> Result<(), JsError> {
        self.signature = Some(transfer.0.signature().ok_or_else(|| JsError::new("transfer is not finished"))?);
        self.transfer = Some(transfer.0);
        Ok(())
    }

    /// The data to send as a stream: the link can be made at once, its
    /// signature is all zeros since the checksum is not known yet. Feed the
    /// data, in order, to `transferUpdate`; at its end `transferFinish` gives the
    /// checksum, and the manifest (now with the size) and the checksum go to
    /// the receivers after the data. Consumes the transfer.
    #[wasm_bindgen(js_name = setStreamingTransfer)]
    pub fn set_streaming_transfer(&mut self, transfer: Transfer) -> Result<(), JsError> {
        if transfer.0.signature().is_some() {
            return Err(JsError::new("a streaming transfer must not be finished"));
        }
        self.signature = Some([0u8; 32]);
        self.transfer = Some(transfer.0);
        Ok(())
    }

    /// The next piece of a streaming transfer's data.
    #[wasm_bindgen(js_name = transferUpdate)]
    pub fn transfer_update(&mut self, chunk: &[u8]) -> Result<(), JsError> {
        self.transfer.as_mut().ok_or_else(|| JsError::new("no transfer set"))?.update(chunk).map_err(js_err)
    }

    /// All of a streaming transfer's data has been fed: its checksum.
    #[wasm_bindgen(js_name = transferFinish)]
    pub fn transfer_finish(&mut self) -> Result<Vec<u8>, JsError> {
        let transfer = self.transfer.as_mut().ok_or_else(|| JsError::new("no transfer set"))?;
        transfer.finish().map(|s| s.to_vec()).map_err(js_err)
    }

    /// The share link (base64url fragment) of the transfer.
    #[wasm_bindgen(js_name = linkB64)]
    pub fn link_b64(&self) -> Result<String, JsError> {
        let signature = self.signature.ok_or_else(|| JsError::new("no transfer set"))?;
        Ok(bx::ShareLink::new(bx::ShareKey(self.core.share_key().0), signature).to_b64_url())
    }

    #[wasm_bindgen(js_name = numBlocks)]
    pub fn num_blocks(&self) -> Result<u32, JsError> {
        Ok(self.sending()?.num_blocks())
    }

    /// `[start, length]` of a block in the data.
    #[wasm_bindgen(js_name = blockSpan)]
    pub fn block_span(&self, block_nr: u32) -> Result<Array, JsError> {
        let (start, len) = self.sending()?.block_span(block_nr);
        Ok([JsValue::from_f64(start as f64), JsValue::from_f64(len as f64)].into_iter().collect())
    }

    /// Relay frames for a block of the data (`pass` counts the times the
    /// block has been sent before). Append them to the upload as they are.
    #[wasm_bindgen(js_name = encodeBlock)]
    pub fn encode_block(&self, block_nr: u32, block: &[u8], pass: u32) -> Result<Vec<u8>, JsError> {
        self.sending()?.encode_block(block_nr, block, pass).map_err(js_err)
    }

    fn sending(&self) -> Result<&data::Outgoing, JsError> {
        self.transfer.as_ref().ok_or_else(|| JsError::new("no transfer set"))
    }

    // -- receiver --

    /// A decoder for the relay stream of the transfer the sender announced.
    pub fn incoming(&self) -> Result<RelayDecoder, JsError> {
        let manifest = self.core.manifest.as_ref().ok_or_else(|| JsError::new("no manifest received yet"))?;
        Ok(RelayDecoder(data::Incoming::new(manifest).map_err(js_err)?))
    }

    /// Checks the received data (fed in order) against the share link's
    /// signature, or, for a streaming transfer, against the `checksum` the sender
    /// sent after the data.
    pub fn verifier(&self, checksum: Option<Vec<u8>>) -> Result<Verifier, JsError> {
        let manifest = self.core.manifest.as_ref().ok_or_else(|| JsError::new("no manifest received yet"))?;
        let signature = match checksum {
            Some(checksum) => array_32(&checksum, "checksum")?,
            None => self.signature.ok_or_else(|| JsError::new("the link has no signature"))?,
        };
        // a link made for a stream has no signature to check against
        if signature == [0u8; 32] {
            return Err(JsError::new("there is nothing to check the data against: no signature, no checksum"));
        }
        Ok(Verifier(Some(data::Verifier::new(manifest, signature))))
    }
}

/// Decodes the relay's byte stream into blocks of the file.
#[wasm_bindgen]
pub struct RelayDecoder(data::Incoming);

#[wasm_bindgen]
impl RelayDecoder {
    /// The next bytes come from a new connection: forget a frame that was cut off.
    #[wasm_bindgen(js_name = newStream)]
    pub fn new_stream(&mut self) {
        self.0.new_stream();
    }

    /// Feed bytes of the stream (any chunking). Returns the blocks completed
    /// by them, as `{offset, data}`.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Array, JsError> {
        let blocks = self.0.push(chunk).map_err(js_err)?;
        let out = Array::new();
        for block in blocks {
            let o = Object::new();
            set(&o, "offset", block.offset as f64);
            set(&o, "data", bytes(&block.data));
            out.push(&o);
        }
        Ok(out)
    }

    #[wasm_bindgen(js_name = isComplete)]
    pub fn is_complete(&self) -> bool {
        self.0.is_complete()
    }

    /// Numbers of the blocks decoded so far.
    #[wasm_bindgen(js_name = doneBlocks)]
    pub fn done_blocks(&self) -> Vec<u32> {
        self.0.done_blocks()
    }
}

#[wasm_bindgen]
pub struct Verifier(Option<data::Verifier>);

#[wasm_bindgen]
impl Verifier {
    pub fn update(&mut self, chunk: &[u8]) -> Result<(), JsError> {
        self.0.as_mut().ok_or_else(|| JsError::new("already finished"))?.update(chunk);
        Ok(())
    }

    /// Is the data what the link committed to?
    pub fn finish(&mut self) -> Result<bool, JsError> {
        Ok(self.0.take().ok_or_else(|| JsError::new("already finished"))?.finish())
    }
}

// ---- events and messages as JS objects --------------------------------

fn event_to_js(event: Event) -> JsValue {
    let o = Object::new();
    match event {
        Event::Out(data) => {
            set(&o, "kind", "out");
            set(&o, "bytes", bytes(&data));
        }
        Event::Created { reconnect_token, relay_token } => {
            set(&o, "kind", "created");
            set(&o, "reconnectToken", reconnect_token.as_hex());
            set(&o, "relayToken", relay_token.as_hex());
        }
        Event::Joined { sender, sender_caps, relay_token } => {
            set(&o, "kind", "joined");
            set(&o, "sender", sender.as_hex());
            set(&o, "senderCaps", sender_caps.bits());
            set(&o, "relayToken", relay_token.as_hex());
        }
        Event::PeerJoined { id, caps } => {
            set(&o, "kind", "peerJoined");
            set(&o, "id", id.as_hex());
            set(&o, "caps", caps.bits());
        }
        Event::PeerReady { id } => {
            set(&o, "kind", "peerReady");
            set(&o, "id", id.as_hex());
        }
        Event::Message { from, message } => {
            set(&o, "kind", "message");
            set(&o, "from", from.as_hex());
            set(&o, "message", message_to_js(&message));
        }
        Event::PeerLeft { id } => {
            set(&o, "kind", "peerLeft");
            set(&o, "id", id.as_hex());
        }
        Event::PeerFull { id } => {
            set(&o, "kind", "peerFull");
            set(&o, "id", id.as_hex());
        }
        Event::Text(text) => {
            set(&o, "kind", "text");
            set(&o, "text", text);
        }
    }
    o.into()
}

fn message_to_js(message: &Peer2Peer) -> JsValue {
    let o = Object::new();
    let ty = |name: &str| set(&o, "type", name);
    match message {
        Peer2Peer::IceCandidate(candidate) => {
            ty("IceCandidate");
            set(&o, "candidate", candidate.as_str());
        }
        Peer2Peer::SdpOffer(SdpOffer { sdp }) => {
            ty("SdpOffer");
            set(&o, "sdp", sdp.as_str());
        }
        Peer2Peer::SdpAnswer(SdpAnswer { sdp }) => {
            ty("SdpAnswer");
            set(&o, "sdp", sdp.as_str());
        }
        Peer2Peer::Manifest(manifest) => {
            ty("Manifest");
            set(&o, "size", manifest.transfer_size as f64);
            set(&o, "blockSize", manifest.block_size);
            // already made safe to use as a file name; null if there is none
            set(&o, "name", manifest.file_name().map(JsValue::from).unwrap_or(JsValue::NULL));
            set(&o, "kind", match data::Kind::of(manifest) {
                data::Kind::Single => "single",
                data::Kind::Zip => "zip",
            });
        }
        Peer2Peer::Get { start, end } => {
            ty("Get");
            set(&o, "start", *start as f64);
            set(&o, "end", *end as f64);
        }
        Peer2Peer::InlineData { start, data } => {
            ty("InlineData");
            set(&o, "start", *start as f64);
            set(&o, "data", bytes(data));
        }
        Peer2Peer::JoinRelay => ty("JoinRelay"),
        Peer2Peer::Progress(n) => {
            ty("Progress");
            set(&o, "bytes", *n as f64);
        }
        Peer2Peer::Complete => ty("Complete"),
        Peer2Peer::ShareLink(link) => {
            ty("ShareLink");
            set(&o, "link", link.as_str());
        }
        Peer2Peer::UdpHello(UdpHello { addrs }) => {
            ty("UdpHello");
            set(&o, "addrs", addrs.iter().map(|a| JsValue::from_str(a)).collect::<Array>());
        }
        Peer2Peer::Checksum(sum) => {
            ty("Checksum");
            set(&o, "checksum", Uint8Array::from(&sum[..]));
        }
    }
    o.into()
}

fn field(object: &JsValue, key: &str) -> Result<JsValue, JsError> {
    Reflect::get(object, &key.into()).map_err(|_| JsError::new(&format!("message has no {key:?}")))
}

fn string_field(object: &JsValue, key: &str) -> Result<String, JsError> {
    field(object, key)?.as_string().ok_or_else(|| JsError::new(&format!("{key:?} must be a string")))
}

fn number_field(object: &JsValue, key: &str) -> Result<u64, JsError> {
    let n = field(object, key)?.as_f64().ok_or_else(|| JsError::new(&format!("{key:?} must be a number")))?;
    if n < 0.0 || n.fract() != 0.0 {
        return Err(JsError::new(&format!("{key:?} must be a whole number")));
    }
    Ok(n as u64)
}

/// `Manifest` is accepted without fields: `Session.send` fills it in.
fn message_from_js(message: &JsValue) -> Result<Peer2Peer, JsError> {
    Ok(match string_field(message, "type")?.as_str() {
        "IceCandidate" => Peer2Peer::IceCandidate(string_field(message, "candidate")?),
        "SdpOffer" => Peer2Peer::SdpOffer(SdpOffer { sdp: string_field(message, "sdp")? }),
        "SdpAnswer" => Peer2Peer::SdpAnswer(SdpAnswer { sdp: string_field(message, "sdp")? }),
        "Manifest" => Peer2Peer::Manifest(bitmule_core::protocol::websocket::TransferManifest {
            transfer_typ: bitmule_core::protocol::websocket::TransferType::SingleFile { compression: None },
            block_size: 0,
            transfer_size: 0,
            bulk_key: bx::BulkKey::random(),
            block_hashes: Vec::new(),
            name: None,
        }),
        "Get" => Peer2Peer::Get { start: number_field(message, "start")?, end: number_field(message, "end")? },
        "InlineData" => Peer2Peer::InlineData {
            start: number_field(message, "start")?,
            data: Uint8Array::new(&field(message, "data")?).to_vec().into(),
        },
        "JoinRelay" => Peer2Peer::JoinRelay,
        "Progress" => Peer2Peer::Progress(number_field(message, "bytes")?),
        "Complete" => Peer2Peer::Complete,
        "ShareLink" => Peer2Peer::ShareLink(string_field(message, "link")?),
        "UdpHello" => Peer2Peer::UdpHello(UdpHello {
            addrs: Array::from(&field(message, "addrs")?).iter().filter_map(|a| a.as_string()).collect(),
        }),
        "Checksum" => {
            let bytes = Uint8Array::new(&field(message, "checksum")?).to_vec();
            Peer2Peer::Checksum(bytes.try_into().map_err(|_| JsError::new("a checksum is 32 bytes"))?)
        }
        other => return Err(JsError::new(&format!("unknown message type {other:?}"))),
    })
}

// keep the proof of work reachable for tests of the server contract
#[allow(dead_code)]
fn _pow_is_linked() -> bool {
    pow::verify_c(&bitmule_core::SessionId([0; 32]), 0, 0, 0)
}
