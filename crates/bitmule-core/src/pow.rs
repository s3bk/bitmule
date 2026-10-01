
use sha2::{Digest, Sha256, block_api::compress256};
use crate::SessionId;

/// SHA-256(session_id || nonce.to_le_bytes()) must have >= difficulty leading
/// zero bits. Rough single-core cost:
///   20 bits ~1M hashes  (~<1s)
///   22 bits ~4M hashes  (~2-3s)
///   24 bits ~16M hashes (~10s)

pub fn verify(session_id: &SessionId, magic: u32, nonce: u64, difficulty: u8) -> bool {
    let mut h = Sha256::new();
    h.update(session_id.0);
    h.update(nonce.to_le_bytes());
    h.update(magic.to_le_bytes());
    let mut hash: [u8; 32] = h.finalize().into();
    hash.iter_mut().zip(SECRET).for_each(|(a, b)| *a ^= *b);
    leading_zero_bits(&hash) >= difficulty as u32
}

pub fn solve(session_id: &SessionId, magic: u32, difficulty: u8) -> u64 {
    (0u64..).find(|&n| verify(session_id, magic, n, difficulty)).unwrap()
}

const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    0x5be0cd19,
];


/// SECRET as eight big-endian u32 words (matches compress256's state).
const SECRET_W32: [u32; 8] = {
    let mut out = [0u32; 8];
    let mut i = 0;
    while i < 8 {
        out[i] = u32::from_be_bytes([
            SECRET[4 * i],
            SECRET[4 * i + 1],
            SECRET[4 * i + 2],
            SECRET[4 * i + 3],
        ]);
        i += 1;
    }
    out
};
pub fn verify_c(session_id: &SessionId, magic: u32, nonce: u64, difficulty: u8) -> bool {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(&session_id.0);
    block[32..40].copy_from_slice(&nonce.to_le_bytes());
    block[40..44].copy_from_slice(&magic.to_le_bytes());
    block[44] = 0x80;
    block[56..].copy_from_slice(&(44u64 * 8).to_be_bytes());

    let mut st = SHA256_IV;
    compress256(&mut st, core::slice::from_ref(&block));

    // st holds the digest as 8 big-endian-order u32 words.
    let w: [u32; 8] = core::array::from_fn(|i| st[i] ^ SECRET_W32[i]);

    c_original(&w) >= difficulty as u32
}

pub fn solve_c(
    session_id: &[u8; 32],
    magic: u32,
    difficulty: u8,
) -> u64 {
    // Message is 32 (session) + 8 (nonce) + 4 (magic) = 44 bytes: one block.
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(session_id);
    // block[32..40] = nonce (patched per attempt)
    block[40..44].copy_from_slice(&magic.to_le_bytes());
    block[44] = 0x80;
    block[56..].copy_from_slice(&(44u64 * 8).to_be_bytes());

    (0u64..)
        .find(|&n| {
            block[32..40].copy_from_slice(&n.to_le_bytes());

            let mut st = SHA256_IV;
            compress256(&mut st, core::slice::from_ref(&block));

            // st holds the digest as 8 big-endian-order u32 words.
            let w: [u32; 8] = core::array::from_fn(|i| st[i] ^ SECRET_W32[i]);

            c_original(&w) >= difficulty as u32
        })
        .unwrap()
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
pub fn c_original(w: &[u32; 8]) -> u32 {
    let mut n = 0;
    for x in w {
        let lz = x.leading_zeros();
        n += lz;
        if lz != 32 {
            break;
        }
    }
    n
}
