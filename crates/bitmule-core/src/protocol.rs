use crate::{Error, Result};
use rand::RngCore;
use roaring::RoaringBitmap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Unique identifier for a transfer session.
///
/// Held as a fixed 32-byte array so that filesystem mappings can rely on a
/// bounded, structurally-safe representation. Wire form is a lowercase hex
/// string, which is also what maps 1:1 onto a directory name (no path
/// separators, no `..`, no NULs, no unicode surprises).
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct SessionId(pub [u8; 32]);

/// Identifies one receiver in a one-to-many transfer session. Same shape
/// discipline as [`SessionId`].
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct ReceiverId(pub [u8; 32]);

impl SessionId {
    pub const SIZE: usize = 32;
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        Self(buf)
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let v = hex::decode(s).map_err(|e| Error::Protocol(format!("session hex: {e}")))?;
        if v.len() != 32 {
            return Err(Error::Protocol(format!(
                "session id must be 32 bytes, got {}",
                v.len()
            )));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&v);
        Ok(Self(buf))
    }
}

impl ReceiverId {
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        Self(buf)
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let v = hex::decode(s).map_err(|e| Error::Protocol(format!("receiver hex: {e}")))?;
        if v.len() != 32 {
            return Err(Error::Protocol(format!(
                "receiver id must be 32 bytes, got {}",
                v.len()
            )));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&v);
        Ok(Self(buf))
    }
}

impl Serialize for SessionId {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        self.as_hex().serialize(s)
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for ReceiverId {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        self.as_hex().serialize(s)
    }
}

impl<'de> Deserialize<'de> for ReceiverId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Bitmap of received chunks. Roaring for efficiency at TB-scale.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChunkBitmap {
    /// Global chunk-index → 1 bit per chunk across the entire manifest.
    /// Compact for both dense (fresh transfer) and sparse (resuming late-stage) cases.
    #[serde(with = "roaring_serde")]
    pub bits: RoaringBitmap,
}

impl ChunkBitmap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, global_chunk_idx: u32) {
        self.bits.insert(global_chunk_idx);
    }

    pub fn has(&self, global_chunk_idx: u32) -> bool {
        self.bits.contains(global_chunk_idx)
    }

    pub fn missing_up_to(&self, total: u32) -> Vec<u32> {
        (0..total).filter(|i| !self.bits.contains(*i)).collect()
    }
}

mod roaring_serde {
    use roaring::RoaringBitmap;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(b: &RoaringBitmap, s: S) -> Result<S::Ok, S::Error> {
        let mut buf = Vec::new();
        b.serialize_into(&mut buf).map_err(serde::ser::Error::custom)?;
        buf.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<RoaringBitmap, D::Error> {
        let buf: Vec<u8> = Vec::deserialize(d)?;
        RoaringBitmap::deserialize_from(&buf[..]).map_err(serde::de::Error::custom)
    }
}

pub mod relay_frame {
    #[repr(u8)]
    pub enum FrameType {
        Data = 1,
        SelectionUpdate = 2,
        RoutingUpdate = 3,
    }
    pub const F_DATA: u8 = FrameType::Data as u8;
    pub const F_SELECTION_UPDATE: u8 = FrameType::SelectionUpdate as u8;
    pub const F_ROUTING_UPDATE: u8 = FrameType::RoutingUpdate as u8;

    pub type FrameSize = u16;
    pub const FRAME_SIZE_BYTES: usize = size_of::<FrameSize>();
}

pub mod websocket {
    use bitflags::bitflags;
    use bytes::Bytes;

    use bitmule_crypto::BulkKey;
    use crate::{ContentKey, ReceiverId, SessionId, crypto::{PublicKey, SessionMac}, inner::{Envelope, InnerKeyKind, OuterKeyKind}};

    bitflags! {
        pub struct PeerCaps: u8 {
            const RELAY = 1;
            const WEBRTC = 2;
        }
    }

    // wire-version part of the url
    // session-id part of URL
    // pow part of URL
    // pow difficulto obtained via GET before connecting
    enum ClientToServer {
        /*
            * server stores public-keys of session creator
            * and sends it to joining peers
            */
        CreateSession {
            id: ReceiverId,
            capabilities: PeerCaps,
            pub_key: PublicKey,
            mac: SessionMac,
        },
        JoinSession {
            id: ReceiverId,
            capabilities: PeerCaps,
            pub_key: PublicKey,
            mac: SessionMac,
        },
        SendToX3DH {
            dest_id: ReceiverId,
            // encrypted with dest's public key and signed by senders public key
            msg: Envelope<OuterKeyKind, X3DH>,
        },
        SendTo {
            dest_id: ReceiverId,
            // encrypted with the peers X3DH key
            msg: Envelope<InnerKeyKind, Peer2Peer>,
        }
    }
    enum ServerToClient {
        SessionCreated,
        // we just joined a session, here is the info of the session owner
        SessionJoined {
            sender_id: ReceiverId,
            sender_pub_key: PublicKey,
            sender_mac: SessionMac,
        },
        // a peer has joined a session that we created
        PeerJoined {
            id: ReceiverId,
            pub_key: PublicKey,
            mac: SessionMac,
        },
        // someone sent us a message
        PeerMessageX3DH {
            from: ReceiverId,
            data: Envelope<OuterKeyKind, X3DH>,
        },
        PeerMessage {
            from: ReceiverId,
            data: Envelope<InnerKeyKind, Peer2Peer>,
        }
    }
    struct X3DH {
        /// Initiator sends its X25519 ephemeral. Runs after the initiator
        /// has verified the counterpart's pub_key via `mac = HMAC(A, pub_key)`
        /// from PeerJoined — otherwise no point (nothing to bind identity to).

        /// Responder sends its X25519 ephemeral. Both sides now hold
        /// (IK_A, IK_B, EK_A, EK_B) and derive:
        ///   DH1 = DH(IK_a_priv, EK_b_pub)   // static-a × ephemeral-b
        ///   DH2 = DH(EK_a_priv, IK_b_pub)   // ephemeral-a × static-b
        ///   DH3 = DH(EK_a_priv, EK_b_pub)   // ephemeral-a × ephemeral-b
        ///   session_key = HKDF-SHA256(
        ///       ikm  = DH1 || DH2 || DH3,
        ///       salt = session_id,
        ///       info = b"bitmule-p2p session-key v1" || IK_A_pub || IK_B_pub,
        ///   )
        /// The `IK_A_pub || IK_B_pub` binding in `info` is X3DH's "AD"
        /// (associated data) — prevents identity-key-substitution attacks
        /// where a third party swaps in different IKs but reuses ephemerals.

        ephemeral_pub: [u8; 32],

    }

    enum Peer2Peer {
        // turn into proper struct
        IceCandidate(String),
        SdpOffer(SdpOffer),
        SdpAnswer(SdpAnswer),

        // sender sends this to all connecting receivers
        // inform the receiver what to expect
        Manifest(TransferManifest),

        // receivers send this to the sender
        // request the given range of the data
        Get { start: u64, end: u64 },

        // sender -> client
        // to the facilitate the transfer of small fires via websocket
        InlineData {
            start: u64,
            data: Bytes,
        },

        // sender informs the client to fetch data via relay
        JoinRelay,

        // receiver has completed the transfer (and will exit)
        Complete,
    }
    /// WebRTC session description, offer half. Wire form is the standard
    /// SDP text blob (RFC 8866). The offer/answer distinction is carried
    /// by the enum variant, so we don't repeat a `type` field inside.
    struct SdpOffer {
        sdp: String,
    }
    struct SdpAnswer {
        sdp: String,
    }


    pub struct TransferManifest {
        pub transfer_typ: TransferType,
        pub block_size: u32,
        pub transfer_size: u64,
        pub bulk_key: BulkKey,
    }
    pub enum TransferType {
        SingleFile {
            compression: Option<Compression>,
        },
        MultiFileZip {
            outer_compression: Option<Compression>,
        },
    }
    pub struct FileMeta {
        pub file_name: Option<String>,
        pub file_size: u64, // uncompressed file size
    }
    pub enum Compression {
        Brotli,
        Zstd,
    }
}
