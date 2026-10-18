use std::time::Duration;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use sha2::block_api::compress256;
use sha2::{Digest, Sha256};

use std::hint::black_box;
use criterion::measurement::WallTime;
use criterion::{
    criterion_group, criterion_main, BenchmarkGroup, Criterion, Throughput,
};

const MAGIC: u32 = 0x1234_5678;

// ---------------------------------------------------------------------------
// Implementations
// ---------------------------------------------------------------------------

pub fn original(hash: &[u8; 32]) -> u32 {
    let mut n = 0;
    for b in hash {
        let lz = b.leading_zeros();
        n += lz;
        if lz != 8 {
            break;
        }
    }
    n
}

// ---------------------------------------------------------------------------
// The real proof-of-work code, with the lz function passed in as a value
// ---------------------------------------------------------------------------

const SECRET: &[u8; 32] = b"bitmule-v1-websocket-abcde123456";

#[inline]
pub fn verify<F: Fn(&[u8; 32]) -> u32>(
    lz: F,
    session_id: &[u8; 32],
    magic: u32,
    nonce: u64,
    difficulty: u8,
) -> bool {
    let mut h = Sha256::new();
    h.update(session_id);
    h.update(nonce.to_le_bytes());
    h.update(magic.to_le_bytes());
    let mut hash: [u8; 32] = h.finalize().into();
    hash.iter_mut().zip(SECRET).for_each(|(a, b)| *a ^= *b);
    lz(&hash) >= difficulty as u32
}

pub fn solve<F: Fn(&[u8; 32]) -> u32 + Copy>(
    lz: F,
    session_id: &[u8; 32],
    magic: u32,
    difficulty: u8,
) -> u64 {
    (0u64..)
        .find(|&n| verify(lz, session_id, magic, n, difficulty))
        .unwrap()
}

/// Finalize and view the digest as four big-endian u64 words.
#[inline]
pub fn digest_words(h: Sha256) -> [u64; 4] {
    let d: [u8; 32] = h.finalize().into();
    // SAFETY: same size, alignment 1, every bit pattern valid for u8.
    let w = unsafe { core::mem::transmute::<[u8; 32], [[u8; 8]; 4]>(d) };
    w.map(u64::from_be_bytes)
}

// ---------------------------------------------------------------------------
// compress256 path: build the single SHA-256 block once, patch only the nonce,
// and read the digest straight out of the u32 state (no finalize, no bytes).
// ---------------------------------------------------------------------------

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

pub fn solve_c<F: Fn(&[u32; 8]) -> u32 + Copy>(
    lz: F,
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

            // st is the digest as 8 big-endian-order u32 words; use it as is.
            let w: [u32; 8] = core::array::from_fn(|i| st[i] ^ SECRET_W32[i]);
            lz(&w) >= difficulty as u32
        })
        .unwrap()
}

// ---------------------------------------------------------------------------
// Argon2id path: same search (leading zero bits of the output), but each
// attempt is one memory-hard Argon2id evaluation.
//   password = session_id || nonce (LE) || magic (LE)   (44 bytes)
//   salt     = SECRET                                   (32 bytes)
//   output   = 32 bytes, fed to the usual lz function
// ---------------------------------------------------------------------------

/// OWASP-style baseline: 19 MiB, 2 passes, 1 lane (single lane = no
/// intra-puzzle parallelism for a workstation to exploit).
const ARGON_M_KIB: u32 = 19 * 1024;
const ARGON_T: u32 = 2;
const ARGON_P: u32 = 1;

/// Holds the Argon2 instance and a reusable memory buffer, so the 19 MiB
/// allocation is not paid on every attempt (a real solver would do the same).
pub struct ArgonCtx {
    argon2: Argon2<'static>,
    mem: Vec<Block>,
}

impl ArgonCtx {
    pub fn new(m_kib: u32, t: u32, p: u32) -> Self {
        let params = Params::new(m_kib, t, p, Some(32)).unwrap();
        let mem = vec![Block::default(); params.block_count()];
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        Self { argon2, mem }
    }

    #[inline]
    pub fn hash(&mut self, session_id: &[u8; 32], nonce: u64, magic: u32) -> [u8; 32] {
        let mut pwd = [0u8; 44];
        pwd[..32].copy_from_slice(session_id);
        pwd[32..40].copy_from_slice(&nonce.to_le_bytes());
        pwd[40..].copy_from_slice(&magic.to_le_bytes());

        let mut out = [0u8; 32];
        self.argon2
            .hash_password_into_with_memory(&pwd, SECRET, &mut out, &mut self.mem)
            .unwrap();
        out
    }
}

pub fn solve_argon2<F: Fn(&[u8; 32]) -> u32 + Copy>(
    ctx: &mut ArgonCtx,
    lz: F,
    session_id: &[u8; 32],
    magic: u32,
    difficulty: u8,
) -> u64 {
    (0u64..)
        .find(|&n| lz(&ctx.hash(session_id, n, magic)) >= difficulty as u32)
        .unwrap()
}

// ---------------------------------------------------------------------------
// Dataset generation (no external RNG dependency)
// ---------------------------------------------------------------------------

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn random_hash(&mut self) -> [u8; 32] {
        let mut h = [0u8; 32];
        for chunk in h.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
        h
    }
}

fn session_ids(n: usize) -> Vec<[u8; 32]> {
    let mut rng = XorShift(0xA076_1D64_78BD_642F);
    (0..n).map(|_| rng.random_hash()).collect()
}

fn bench_solver<F>(
    g: &mut BenchmarkGroup<WallTime>,
    name: &str,
    lz: F,
    ids: &[[u8; 32]],
    magic: u32,
    difficulty: u8,
) where
    F: Fn(&[u8; 32]) -> u32 + Copy,
{
    g.bench_function(name, |b| {
        b.iter(|| {
            let mut acc = 0u64;
            for id in black_box(ids) {
                acc = acc.wrapping_add(solve(lz, id, black_box(magic), black_box(difficulty)));
            }
            black_box(acc)
        })
    });
}

fn bench_solver_c<F>(
    g: &mut BenchmarkGroup<WallTime>,
    name: &str,
    lz: F,
    ids: &[[u8; 32]],
    magic: u32,
    difficulty: u8,
) where
    F: Fn(&[u32; 8]) -> u32 + Copy,
{
    g.bench_function(name, |b| {
        b.iter(|| {
            let mut acc = 0u64;
            for id in black_box(ids) {
                acc = acc.wrapping_add(solve_c(lz, id, black_box(magic), black_box(difficulty)));
            }
            black_box(acc)
        })
    });
}

fn bench_solve(c: &mut Criterion) {
    // (difficulty, number of random session ids). Roughly 2^17 expected
    // SHA-256 calls per iteration at every difficulty.
    for (difficulty, count) in [(8u8, 512usize), (12, 32), (16, 2)] {
        let ids = session_ids(count);

        // All implementations must find the same nonce for the same input.
        // Also count the real number of hashes so throughput is in hashes/s.
        let mut hashes = 0u64;
        for id in &ids {
            let want = solve(original, id, MAGIC, difficulty);
            assert_eq!(solve_c(c_original, id, MAGIC, difficulty), want);
            hashes += want + 1;
        }

        let mut g = c.benchmark_group(format!("solve/difficulty_{difficulty}"));
        g.sample_size(30);
        g.throughput(Throughput::Elements(hashes));
        bench_solver(&mut g, "original", original, &ids, MAGIC, difficulty);
        bench_solver_c(&mut g, "compress/original", c_original, &ids, MAGIC, difficulty);
        g.finish();
    }
}

/// Full Argon2id solve. Each attempt costs tens of ms, so difficulties are
/// tiny: ~64 expected attempts per iteration at every difficulty.
fn bench_argon2(c: &mut Criterion) {
    let mut ctx = ArgonCtx::new(ARGON_M_KIB, ARGON_T, ARGON_P);

    for (difficulty, count) in [(2u8, 16usize), (4, 4), (6, 1)] {
        let ids = session_ids(count);

        // Sanity: the nonce found must actually verify. Also count the real
        // number of attempts so throughput is reported in attempts/s.
        let mut attempts = 0u64;
        for id in &ids {
            let nonce = solve_argon2(&mut ctx, original, id, MAGIC, difficulty);
            let h = ctx.hash(id, nonce, MAGIC);
            assert!(original(&h) >= difficulty as u32);
            attempts += nonce + 1;
        }

        let mut g = c.benchmark_group(format!("argon2/difficulty_{difficulty}"));
        g.sample_size(10);
        g.measurement_time(Duration::from_secs(30));
        g.throughput(Throughput::Elements(attempts));
        g.bench_function("argon2id", |b| {
            b.iter(|| {
                let mut acc = 0u64;
                for id in black_box(&ids) {
                    acc = acc.wrapping_add(solve_argon2(
                        &mut ctx,
                        original,
                        id,
                        black_box(MAGIC),
                        black_box(difficulty),
                    ));
                }
                black_box(acc)
            })
        });
        g.finish();
    }
}

/// One Argon2id evaluation at a few memory sizes: the cost of a fixed-cost
/// puzzle with no nonce search (and so no solve-time variance).
fn bench_argon2_single(c: &mut Criterion) {
    let id = session_ids(1)[0];
    let mut g = c.benchmark_group("argon2/single_hash");
    g.sample_size(20);
    for m_kib in [8 * 1024u32, ARGON_M_KIB, 64 * 1024] {
        let mut ctx = ArgonCtx::new(m_kib, ARGON_T, ARGON_P);
        g.bench_function(
            format!("m={}MiB_t={}_p={}", m_kib / 1024, ARGON_T, ARGON_P),
            |b| b.iter(|| black_box(ctx.hash(black_box(&id), black_box(7), black_box(MAGIC)))),
        );
    }
    g.finish();
}

criterion_group!(benches, bench_solve, bench_argon2, bench_argon2_single);
criterion_main!(benches);
