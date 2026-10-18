//! What a UDP receiver tells the sender with its feedback: for each block it
//! is working on, how many more symbols it needs to rebuild it. The sender
//! then sends that many (plus what the path usually loses) instead of passes
//! of a fixed size, so loss costs only the symbols that were lost.

use std::collections::HashMap;

use bytes::Bytes;

/// Symbols beyond the number of source symbols that make a block decode
/// (RaptorQ fails with about 1 in 10^6 at +4).
pub const OVERHEAD: u32 = 4;

/// One block: `block_nr: u32 LE | need: u16 LE`.
const ENTRY: usize = 6;

/// The most blocks one report names.
pub const MAX_BLOCKS: usize = bitmule_client_native::udp::REPORT_MAX / ENTRY;

/// A report for the blocks in `needs`, lowest block numbers first.
pub fn encode(needs: &HashMap<u32, u32>) -> Bytes {
    let mut entries: Vec<_> = needs.iter().filter(|&(_, &need)| need > 0).collect();
    entries.sort();
    let mut out = Vec::with_capacity(entries.len().min(MAX_BLOCKS) * ENTRY);
    for (&block, &need) in entries.into_iter().take(MAX_BLOCKS) {
        out.extend_from_slice(&block.to_le_bytes());
        out.extend_from_slice(&(need.min(u16::MAX as u32) as u16).to_le_bytes());
    }
    Bytes::from(out)
}

/// The needs of a report (a malformed tail is ignored).
pub fn decode(report: &[u8]) -> HashMap<u32, u32> {
    report
        .chunks_exact(ENTRY)
        .map(|e| (u32::from_le_bytes(e[..4].try_into().unwrap()), u16::from_le_bytes(e[4..].try_into().unwrap()) as u32))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_round_trips() {
        let needs: HashMap<u32, u32> = [(3, 20), (900, 1), (7, 0)].into();
        let back = decode(&encode(&needs));
        assert_eq!(back, [(3, 20), (900, 1)].into());
    }

    #[test]
    fn a_report_fits_the_limit() {
        let needs: HashMap<u32, u32> = (0..1000).map(|b| (b, 5)).collect();
        assert!(encode(&needs).len() <= bitmule_client_native::udp::REPORT_MAX);
    }
}
