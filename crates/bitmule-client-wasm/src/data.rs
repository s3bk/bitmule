//! The data plane without I/O: preparing a transfer (key, commitment),
//! encoding blocks for the relay, decoding the relay stream, and checking the
//! result against the share link. Plain Rust; `lib.rs` wraps it for JS.

use anyhow::{Result, ensure};
use bitmule_client_common::fountain;
use bitmule_core::protocol::websocket::{TransferManifest, TransferType};
use bitmule_crypto::{BulkKey, CommitmentHasher};

/// What the sender sends: one file as it is, or several in a zip.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Single,
    Zip,
}

impl Kind {
    pub fn of(manifest: &TransferManifest) -> Kind {
        match manifest.transfer_typ {
            TransferType::SingleFile { .. } => Kind::Single,
            TransferType::MultiFileZip { .. } => Kind::Zip,
        }
    }
}

/// The sender's side of a transfer: a bulk key and the commitment over the
/// data, which the share link carries as its signature.
pub struct Outgoing {
    pub kind: Kind,
    name: Option<String>,
    key: BulkKey,
    hasher: Option<CommitmentHasher>,
    size: u64,
    signature: Option<[u8; 32]>,
    encoder: fountain::Encoder,
}

impl Outgoing {
    pub fn new(kind: Kind, name: Option<String>) -> Self {
        Outgoing {
            kind,
            name,
            key: BulkKey::random(),
            hasher: Some(CommitmentHasher::new()),
            size: 0,
            signature: None,
            encoder: fountain::Encoder::new(),
        }
    }

    /// Feed the data, in order, to compute the commitment.
    pub fn update(&mut self, chunk: &[u8]) -> Result<()> {
        let hasher = self.hasher.as_mut().ok_or_else(|| anyhow::anyhow!("transfer is already finished"))?;
        hasher.update(chunk);
        self.size += chunk.len() as u64;
        Ok(())
    }

    /// All data has been fed. Returns the signature for the share link.
    pub fn finish(&mut self) -> Result<[u8; 32]> {
        let hasher = self.hasher.take().ok_or_else(|| anyhow::anyhow!("transfer is already finished"))?;
        let signature = hasher.finalize(&self.key);
        self.signature = Some(signature);
        Ok(signature)
    }

    pub fn signature(&self) -> Option<[u8; 32]> {
        self.signature
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn manifest(&self) -> TransferManifest {
        let typ = match self.kind {
            Kind::Single => TransferType::SingleFile { compression: None },
            Kind::Zip => TransferType::MultiFileZip { outer_compression: None },
        };
        TransferManifest {
            transfer_typ: typ,
            block_size: fountain::BLOCK_PLAIN as u32,
            transfer_size: self.size,
            bulk_key: self.key.clone(),
            name: self.name.clone(),
        }
    }

    /// Byte range `(start, len)` of block `block_nr` in the data.
    pub fn block_span(&self, block_nr: u32) -> (u64, usize) {
        fountain::block_span(self.size, block_nr)
    }

    pub fn num_blocks(&self) -> u32 {
        fountain::num_blocks(self.size)
    }

    /// Encode block `block_nr` (`data` is its plaintext) as relay frames for
    /// `pass` (0 = source symbols plus a few repair symbols, later passes
    /// fresh repair symbols). The frames are in the relay's wire format, so
    /// they can be appended to an upload as they are.
    pub fn encode_block(&self, block_nr: u32, data: &[u8], pass: u32) -> Result<Vec<u8>> {
        let (_, len) = self.block_span(block_nr);
        ensure!(data.len() == len, "block {block_nr} has {len} bytes, not {}", data.len());
        let mut buf = self.encoder.block_buffer();
        buf[..len].copy_from_slice(data);
        let frames = self.encoder.encode_block(&self.key, block_nr, buf, len)?.frames(pass);
        let mut out = Vec::with_capacity(frames.iter().map(|f| f.len()).sum());
        for frame in frames {
            out.extend_from_slice(&frame);
        }
        Ok(out)
    }
}

/// Decompress one zstd frame.
pub fn zstd_decompress(data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut decoder = ruzstd::decoding::StreamingDecoder::new(data).map_err(|e| anyhow::anyhow!("zstd: {e}"))?;
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).map_err(|e| anyhow::anyhow!("zstd: {e}"))?;
    Ok(out)
}

/// A decoded block: where it goes and what it holds.
pub struct Block {
    pub offset: u64,
    pub data: Vec<u8>,
}

/// Turns the relay's byte stream back into the file, block by block, in the
/// order the blocks complete.
pub struct Incoming {
    splitter: fountain::FrameSplitter,
    decoder: fountain::Decoder,
    pub dropped_symbols: u32,
}

impl Incoming {
    pub fn new(manifest: &TransferManifest) -> Result<Self> {
        ensure!(manifest.block_size as usize == fountain::BLOCK_PLAIN, "sender uses an unsupported block size");
        let decoder = fountain::Decoder::new(
            manifest.bulk_key.clone(),
            manifest.transfer_size,
            Box::new(fountain::MemSpill::default()),
            fountain::symbol_pool(),
        );
        Ok(Incoming { splitter: Default::default(), decoder, dropped_symbols: 0 })
    }

    /// Feed bytes of the relay stream; returns the blocks they completed.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Block>> {
        let mut blocks = vec![];
        for payload in self.splitter.push(bytes)? {
            match self.decoder.push(&payload) {
                Ok(Some(block)) => blocks.push(Block { offset: block.offset(), data: block.data().to_vec() }),
                Ok(None) => {}
                Err(_) => self.dropped_symbols += 1,
            }
        }
        Ok(blocks)
    }

    pub fn is_complete(&self) -> bool {
        self.decoder.is_complete()
    }

    pub fn done_blocks(&self) -> Vec<u32> {
        self.decoder.done_blocks()
    }
}

/// Checks the received data against the signature of the share link.
pub struct Verifier {
    hasher: CommitmentHasher,
    key: BulkKey,
    signature: [u8; 32],
}

impl Verifier {
    pub fn new(manifest: &TransferManifest, signature: [u8; 32]) -> Self {
        Verifier { hasher: CommitmentHasher::new(), key: manifest.bulk_key.clone(), signature }
    }

    /// Feed the data, in order, from the first byte to the last.
    pub fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
    }

    pub fn finish(self) -> bool {
        self.hasher.finalize(&self.key) == self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_roundtrip_with_loss_and_a_short_last_block() {
        let size = fountain::BLOCK_PLAIN * 2 + 12_345;
        let data: Vec<u8> = (0..size as u32).map(|i| i.wrapping_mul(2654435761) as u8).collect();

        let mut out = Outgoing::new(Kind::Single, None);
        for chunk in data.chunks(100_000) {
            out.update(chunk).unwrap();
        }
        let signature = out.finish().unwrap();
        assert_eq!(out.size(), size as u64);
        let manifest = out.manifest();

        let mut incoming = Incoming::new(&manifest).unwrap();
        let mut file = vec![0u8; size];
        let mut pass = 0;
        let mut stream_pos = 0usize;
        while !incoming.is_complete() {
            assert!(pass < 6, "should finish within a few passes");
            for block_nr in 0..out.num_blocks() {
                let (start, len) = out.block_span(block_nr);
                let frames = out.encode_block(block_nr, &data[start as usize..][..len], pass).unwrap();
                // the relay drops whole frames; lose a tenth of them
                let mut rest = &frames[..];
                while !rest.is_empty() {
                    let n = u16::from_le_bytes([rest[0], rest[1]]) as usize + 3;
                    stream_pos += 1;
                    if stream_pos % 10 != 0 {
                        for block in incoming.push(&rest[..n]).unwrap() {
                            file[block.offset as usize..][..block.data.len()].copy_from_slice(&block.data);
                        }
                    }
                    rest = &rest[n..];
                }
            }
            pass += 1;
        }
        assert_eq!(file, data);

        let mut verifier = Verifier::new(&manifest, signature);
        for chunk in file.chunks(65_536) {
            verifier.update(chunk);
        }
        assert!(verifier.finish());
    }

    #[test]
    fn the_manifest_carries_the_name() {
        let out = Outgoing::new(Kind::Single, Some("notes.txt".into()));
        assert_eq!(out.manifest().file_name().as_deref(), Some("notes.txt"));
        assert_eq!(Outgoing::new(Kind::Single, None).manifest().file_name(), None);
    }

    #[test]
    fn zstd_frames_decompress() {
        // printf 'hello hello hello hello hello' | zstd -c
        let frame = [
            0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0x65, 0x00, 0x00, 0x30, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x01, 0x00,
            0xa9, 0x4b, 0x11, 0x87, 0x4e, 0x20, 0x0a,
        ];
        assert_eq!(zstd_decompress(&frame).unwrap(), b"hello hello hello hello hello");
        assert!(zstd_decompress(b"not zstd").is_err());
    }

    #[test]
    fn a_wrong_file_fails_verification() {
        let mut out = Outgoing::new(Kind::Single, None);
        out.update(b"hello").unwrap();
        let signature = out.finish().unwrap();
        let mut verifier = Verifier::new(&out.manifest(), signature);
        verifier.update(b"hellp");
        assert!(!verifier.finish());
    }

    #[test]
    fn frames_survive_arbitrary_chunking() {
        let data = vec![9u8; fountain::BLOCK_PLAIN];
        let mut out = Outgoing::new(Kind::Zip, Some("x.zip".into()));
        out.update(&data).unwrap();
        out.finish().unwrap();
        let manifest = out.manifest();
        assert_eq!(Kind::of(&manifest), Kind::Zip);
        let frames = out.encode_block(0, &data, 0).unwrap();
        let mut incoming = Incoming::new(&manifest).unwrap();
        let mut got = vec![];
        for piece in frames.chunks(1000) {
            got.extend(incoming.push(piece).unwrap());
        }
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data, data);
    }
}
