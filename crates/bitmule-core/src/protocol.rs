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
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        Self(buf)
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
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
