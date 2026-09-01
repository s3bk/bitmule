use roaring::RoaringBitmap;
use serde::{Deserialize, Serialize};

/// Unique identifier for a transfer session (URL-safe base64).
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub String);

/// Identifies one receiver in a one-to-many transfer session.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReceiverId(pub String);

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
