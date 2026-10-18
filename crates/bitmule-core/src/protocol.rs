use crate::{Error};
use bytes::Bytes;
use rand::RngCore;
use roaring::RoaringBitmap;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};

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

/// Server-issued secret handed to a peer in its `SessionCreated` /
/// `SessionJoined` reply. Used as a reconnect token (owner regains its id)
/// and as a relay token (authorizes the relay GET/POST for that peer).
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Token(pub [u8; 16]);

impl Token {
    pub fn random() -> Self {
        let mut buf = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        Self(buf)
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let v = hex::decode(s).map_err(|e| Error::Protocol(format!("token hex: {e}")))?;
        let buf: [u8; 16] = v.try_into().map_err(|v: Vec<u8>| {
            Error::Protocol(format!("token must be 16 bytes, got {}", v.len()))
        })?;
        Ok(Self(buf))
    }
}

impl PartialEq for Token {
    /// Constant time.
    fn eq(&self, other: &Self) -> bool {
        self.0.iter().zip(&other.0).fold(0u8, |d, (a, b)| d | (a ^ b)) == 0
    }
}
impl Eq for Token {}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(..)")
    }
}

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

    pub fn from_hex(s: &str) -> Result<Self, Error> {
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

    pub fn from_hex(s: &str) -> Result<Self, Error> {
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
    }
    pub const F_DATA: u8 = FrameType::Data as u8;

    pub type FrameSize = u16;
    pub const FRAME_SIZE_BYTES: usize = size_of::<FrameSize>();
}

pub mod websocket {
    use bitflags::bitflags;
    use bytes::Bytes;

    use bitmule_crypto::BulkKey;
use serde::{Deserialize, Serialize};
    use crate::{ReceiverId, Token, crypto::{PublicKey, SessionMac}, inner::{Envelope, InnerKeyKind, OuterKeyKind}};

    bitflags! {
        #[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
        pub struct PeerCaps: u8 {
            const RELAY = 1;
            const WEBRTC = 2;
            /// Raw fountain symbols over UDP, straight between the peers (native clients only).
            const UDP = 4;
        }
    }

    // wire-version part of the url
    // session-id part of URL
    // pow part of URL
    // pow difficulto obtained via GET before connecting
    #[derive(Serialize, Deserialize)]
    pub enum ClientToServer {
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
        SendTo1 {
            dest_id: ReceiverId,
            // encrypted with dest's public key and signed by senders public key
            msg: Envelope<OuterKeyKind, ECDH>,
        },
        SendTo2 {
            dest_id: ReceiverId,
            // encrypted with the peers X3DH key
            msg: Envelope<InnerKeyKind, Peer2Peer>,
        }
    }

    #[derive(Serialize, Deserialize)]
    pub enum ServerToClient {
        // just display it or ignore it
        Text(String),

        // reply to CreateSession. To reconnect as owner after a dropped
        // connection, pass `reconnect_token` as `?token=` to /ws/create.
        // `relay_token` authorizes the relay POST (`?token=`).
        SessionCreated {
            reconnect_token: Token,
            relay_token: Token,
        },
        // we just joined a session, here is the info of the session owner
        SessionJoined {
            // authorizes the relay GET (`?token=`)
            relay_token: Token,
            sender_id: ReceiverId,
            sender_pub_key: PublicKey,
            sender_mac: SessionMac,
            sender_caps: PeerCaps,
        },
        // a peer has joined a session that we created
        PeerJoined {
            id: ReceiverId,
            pub_key: PublicKey,
            mac: SessionMac,
            caps: PeerCaps,
        },
        // someone sent us a message
        PeerMessage1 {
            from: ReceiverId,
            data: Envelope<OuterKeyKind, ECDH>,
        },
        PeerMessage2 {
            from: ReceiverId,
            data: Envelope<InnerKeyKind, Peer2Peer>,
        },
        PeerFull {
            id: ReceiverId
        },
        PeerDisconnected {
            id: ReceiverId
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct ECDH {
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

        pub ephemeral_pub: PublicKey,

    }

    #[derive(Serialize, Deserialize)]
    pub enum Peer2Peer {
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

        Progress(u64),
        // receiver has completed the transfer (and will exit)
        Complete,

        // sender -> requester (receiver-initiated flow): the share link
        // (base64url) of the session the sender created for the transfer
        ShareLink(String),

        // both ways, before a UDP transfer: where this peer can be reached
        UdpHello(UdpHello),

        // sender -> receiver, last message of a streaming transfer, after its
        // `Manifest`: SHA256(data || bulk_key), the data's commitment. A
        // normal transfer carries it in the share link instead.
        Checksum([u8; 32]),
    }

    /// The addresses (`ip:port`) a peer's UDP sockets can be reached at: its
    /// own interfaces and, if STUN told it, the public ones.
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct UdpHello {
        pub addrs: Vec<String>,
    }
    /// WebRTC session description, offer half. Wire form is the standard
    /// SDP text blob (RFC 8866). The offer/answer distinction is carried
    /// by the enum variant, so we don't repeat a `type` field inside.
    #[derive(Serialize, Deserialize)]
    pub struct SdpOffer {
        pub sdp: String,
    }
    #[derive(Serialize, Deserialize)]
    pub struct SdpAnswer {
        pub sdp: String,
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct TransferManifest {
        pub transfer_typ: TransferType,
        pub block_size: u32,
        pub transfer_size: u64,
        pub bulk_key: BulkKey,
        /// What the sender calls the file (or the zip). Use [`TransferManifest::file_name`]
        /// to save it: this is whatever the peer sent.
        pub name: Option<String>,
    }

    impl TransferManifest {
        /// `name` made safe to use as a file name in a directory: no path
        /// components, no control characters, not empty, not too long. `None`
        /// if nothing usable is left.
        pub fn file_name(&self) -> Option<String> {
            sanitize_file_name(self.name.as_deref()?)
        }
    }

    pub fn sanitize_file_name(name: &str) -> Option<String> {
        // the last component, whichever separator the sender's system uses
        let last = name.rsplit(['/', '\\']).next().unwrap_or("");
        let cleaned: String = last.chars().filter(|c| !c.is_control() && !matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|')).collect();
        let cleaned = cleaned.trim().trim_matches('.').trim();
        if cleaned.is_empty() {
            return None;
        }
        // 200 bytes, on a character boundary
        let mut end = cleaned.len().min(200);
        while !cleaned.is_char_boundary(end) {
            end -= 1;
        }
        Some(cleaned[..end].to_string())
    }

    #[cfg(test)]
    mod name_tests {
        use super::sanitize_file_name as clean;

        #[test]
        fn names_lose_paths_and_oddities() {
            assert_eq!(clean("photo.jpg").as_deref(), Some("photo.jpg"));
            assert_eq!(clean("../../etc/passwd").as_deref(), Some("passwd"));
            assert_eq!(clean("C:\\Users\\me\\a.txt").as_deref(), Some("a.txt"));
            assert_eq!(clean("a\nb\0c.txt").as_deref(), Some("abc.txt"));
            assert_eq!(clean("..").as_deref(), None);
            assert_eq!(clean("/").as_deref(), None);
            assert_eq!(clean("").as_deref(), None);
            assert_eq!(clean(".hidden").as_deref(), Some("hidden"));
            assert_eq!(clean(&"é".repeat(300)).unwrap().len(), 200);
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
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

    #[derive(Serialize, Deserialize, Clone)]
    pub enum Compression {
        Zstd,
    }
}

pub struct Encoded<T> {
    value: T,
    bytes: Bytes,
}
impl<T> std::ops::Deref for Encoded<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
impl<T: Serialize> From<T> for Encoded<T> {
    fn from(value: T) -> Self {
        let bytes = postcard::to_stdvec(&value).unwrap().into();
        Encoded { value, bytes }
    }
}
impl<T> Serialize for Encoded<T> {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: Serializer
    {
        self.bytes.serialize(serializer)
    }
}
impl<'de, T> Deserialize<'de> for Encoded<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;

        let bytes = Bytes::deserialize(deserializer)?;
        let value = postcard::from_bytes::<T>(&bytes).map_err(D::Error::custom)?;
        Ok(Encoded { value, bytes })
    }
}
