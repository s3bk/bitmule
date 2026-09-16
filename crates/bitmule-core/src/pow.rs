
use sha2::{Digest, Sha256};
use crate::SessionId;

/// SHA-256(session_id || nonce.to_le_bytes()) must have >= difficulty leading
/// zero bits. Rough single-core cost:
///   20 bits ~1M hashes  (~<1s)
///   22 bits ~4M hashes  (~2-3s)
///   24 bits ~16M hashes (~10s)
pub fn verify(session_id: &SessionId, nonce: u64, difficulty: u32) -> bool {
    let mut h = Sha256::new();
    h.update(session_id.0);
    h.update(nonce.to_le_bytes());
    let mut hash: [u8; 32] = h.finalize().into();
    hash.iter_mut().zip(SECRET).for_each(|(a, b)| *a ^= *b);
    leading_zero_bits(&hash) >= difficulty
}

pub fn solve(session_id: &SessionId, difficulty: u32) -> u64 {
    (0u64..).find(|&n| verify(session_id, n, difficulty)).unwrap()
}

const SECRET: &[u8; 32] = b"bitmule-v1-websocket-abcde123456";
fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut n = 0;
    for b in hash {
        let lz = b.leading_zeros();
        n += lz;
        if lz != 8 { break; }
    }
    n
}
