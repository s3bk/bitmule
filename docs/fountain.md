Let me look at the DataOperator trait and Operation enum, since those are central to efficient disk persistence.Now I have the full picture. Let me also check the `fountain_utility` `IoDataOperator` and `VecDataOperator` since those are the reference implementations.Now I have everything I need. Here's a thorough, practical answer.

---

## Full design: persisting `RaptorQDecoder` state for large file transfer

### Block size recommendation first

With 8 kB symbols and blocks of "several MB", the right target is whatever makes K (source symbols per block) land in the **1 000 – 8 000** range. RFC 6330 supports K up to 56 403; the solver is fast across that range, but the overhead factor (symbols needed beyond K to decode) is lowest and most predictable around K = 1 000–4 000. A concrete recommendation:

| File size | Block size | K (at 8 kB/symbol) |
|-----------|-----------|-------------------|
| < 100 MB  | 4 MB      | 512 — often too small, bumps overhead |
| 100 MB–10 GB | **16 MB** | **2 048** ← sweet spot |
| > 10 GB   | **32 MB** | **4 096** |

**Use 16 MB blocks (K ≈ 2 048).** At that size, the "decoder state" for one in-progress block is at most ~16 MB of symbol data — entirely manageable to rewrite on every iteration.

---

### The right architecture: a file-backed `DataOperator`

The key insight from the docs: the engine is data-free by design — instead of operating on data directly, the encoder and decoder emit a sequence of `Operation` values that a `DataOperator` executes on actual data vectors. This separation enables in-memory operation, I/O logging, network streaming, or any custom backend.

This means you implement a **custom `DataOperator` backed by a memory-mapped file**. The operator holds the live symbol matrix in a file that is the checkpoint. There is no separate "save" step — the file *is* the state.

```
decoder_block_N.bin   ← one file per in-progress block
  [header: 64 bytes]  ← K, block_id, num_received, symbol_len
  [slot 0: 8192 bytes]
  [slot 1: 8192 bytes]
  ...
  [slot MAX_DATA_ID: 8192 bytes]
```

The `DataOperator::execute` method applies each `Operation` in-place on the mapped region, so every XOR, move, copy is written directly to disk via the OS page cache. The OS flushes in the background; you call `msync` once before exit.

---

### Implementation sketch

```rust
use std::fs::OpenOptions;
use memmap2::MmapMut;
use fountain_engine::{DataOperator, Operation};

/// Number of data vector slots to reserve (>= params.L for RaptorQ)
const NUM_SLOTS: usize = 8192;

pub struct MmapDataOperator {
    mmap: MmapMut,
    symbol_len: usize,
    // slot 0..NUM_SLOTS each hold symbol_len bytes
}

impl MmapDataOperator {
    pub fn create(path: &str, symbol_len: usize) -> Self {
        let file_size = NUM_SLOTS * symbol_len;
        let file = OpenOptions::new()
            .read(true).write(true).create(true)
            .open(path).unwrap();
        file.set_len(file_size as u64).unwrap();
        let mmap = unsafe { MmapMut::map_mut(&file).unwrap() };
        Self { mmap, symbol_len }
    }

    pub fn open(path: &str, symbol_len: usize) -> Self {
        let file = OpenOptions::new().read(true).write(true).open(path).unwrap();
        let mmap = unsafe { MmapMut::map_mut(&file).unwrap() };
        Self { mmap, symbol_len }
    }

    fn slot(&mut self, data_id: usize) -> &mut [u8] {
        let off = data_id * self.symbol_len;
        &mut self.mmap[off..off + self.symbol_len]
    }

    fn slot2(&self, data_id: usize) -> &[u8] {
        let off = data_id * self.symbol_len;
        &self.mmap[off..off + self.symbol_len]
    }

    pub fn flush(&self) {
        self.mmap.flush().unwrap();
    }
}

impl DataOperator for MmapDataOperator {
    fn insert_vector(&mut self, vector: &[u8], data_id: usize) {
        self.slot(data_id).copy_from_slice(vector);
    }

    fn get_vector(&self, data_id: usize) -> &[u8] {
        self.slot2(data_id)
    }

    fn execute(&mut self, op: &Operation) {
        match op {
            Operation::EnsureZeroOne { id } => {
                self.slot(*id).fill(0);
            }
            Operation::EnsureZero { list_id } => {
                for &id in list_id { self.slot(id).fill(0); }
            }
            Operation::AddOneToVector { src_id, target_id } => {
                // can't borrow two slots simultaneously — use split_at_mut or temp
                let (s, t) = (*src_id, *target_id);
                let src = self.slot2(s).to_owned(); // small, stack-friendly via SmallVec
                let dst = self.slot(t);
                dst.iter_mut().zip(src.iter()).for_each(|(d, s)| *d ^= s);
            }
            Operation::MoveTo { src_id, target_id } => {
                if src_id != target_id {
                    let src = self.slot2(*src_id).to_owned();
                    self.slot(*target_id).copy_from_slice(&src);
                    self.slot(*src_id).fill(0);
                }
            }
            Operation::CopyTo { src_id, target_id } => {
                if src_id != target_id {
                    let src = self.slot2(*src_id).to_owned();
                    self.slot(*target_id).copy_from_slice(&src);
                }
            }
            Operation::Remove { id } => {
                self.slot(*id).fill(0); // just zero it; slot is reusable
            }
            // AddTwo, AddThree, AddToVector, BroadcastAdd, MulAdd,
            // MultiplyAlpha, MultiplyScalar — implement similarly
            _ => { /* handle remaining variants */ }
        }
    }
}
```

---

### The checkpoint header (separate small file)

The mmap file holds the symbol matrix. Alongside it, keep a tiny header file (serialised with `postcard`) that records everything needed to reconstruct the decoder wrapper — you can't recover this from the symbol data alone:

```rust
#[derive(serde::Serialize, serde::Deserialize)]
struct BlockCheckpoint {
    block_id: u64,
    num_source: usize,        // K for this block
    symbol_len: usize,        // 8192
    num_received: usize,      // = decoder.inner.manager.num_coded_vector_inserted
    // the coded_id sequence, in order received
    received_coded_ids: Vec<usize>,
}
```

Write this with `postcard::to_stdvec` + `std::fs::write`. It's tiny (a few KB even for thousands of symbols).

---

### Per-iteration loop

```rust
loop {
    // --- RESTORE ---
    let checkpoint: BlockCheckpoint = postcard::from_bytes(
        &std::fs::read("block_N.chk")?
    )?;
    let op = MmapDataOperator::open("block_N.bin", checkpoint.symbol_len);
    // Rebuild the decoder shell (no data replay — data is already in the mmap file)
    let mut decoder = RaptorQDecoder::new_with_operator_execute_only(
        my_scheme.clone(),
        Box::new(op),
        checkpoint.symbol_len,
    );
    // Re-register coded IDs so the manager's ID map is consistent
    // (no data XOR needed — just re-feed add_coded_id, not add_coded_vector)
    for coded_id in &checkpoint.received_coded_ids {
        decoder.add_coded_id(*coded_id);
    }

    // --- PROGRESS CHECK ---
    let still_needed = checkpoint.num_source
        .saturating_sub(checkpoint.num_received);
    if still_needed == 0 || decoder.decode_status() == DecodeStatus::Decoded {
        // write output from decoder.get_data_vector(i) for i in 0..num_source
        break;
    }
    println!("{} symbols still needed", still_needed);

    // --- RECEIVE MORE ---
    let (coded_id, symbol_data) = receive_next_symbol();
    decoder.add_coded_vector(coded_id, &symbol_data);

    // --- PERSIST ---
    // mmap is already updated (DataOperator::execute fired on add_coded_vector)
    decoder.inner.manager.num_coded_vector_inserted; // read for checkpoint
    let new_checkpoint = BlockCheckpoint {
        received_coded_ids: /* append coded_id */,
        num_received: decoder.inner.manager.num_coded_vector_inserted,
        ..checkpoint
    };
    op_ref.flush(); // msync the mmap
    std::fs::write("block_N.chk", postcard::to_stdvec(&new_checkpoint)?)?;
}
```

> **Note:** `add_coded_id` re-feeds the solver graph edges without touching the data vectors — so restoring is O(num_received × graph_work), not O(num_received × symbol_len). This is fast even for thousands of symbols.

---

### Space cost

| Component | Size |
|---|---|
| mmap symbol file | `NUM_SLOTS × symbol_len` = 8192 × 8192 = **64 MB** |
| checkpoint header | `~num_received × 8 bytes` ≈ **tens of KB** |

64 MB per in-progress block is the worst case and is essentially the same as the block data itself — there's no redundancy. Once decoded, delete both files.

### CPU cost per iteration

- Receiving 1 symbol → 1 `add_coded_vector` call → solver emits a handful of `Operation`s → each writes directly into the mmap. **No separate save step. No serialisation of symbol data.**
- Restoring → open mmap (zero copy) + replay `add_coded_id` sequence (graph only, no data). For 2 048 symbols at K = 2 048 this takes a few milliseconds.
