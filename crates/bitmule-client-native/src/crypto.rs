//! End-to-end encryption for bitmule transfers.
//!
//! Moved to the shared `bitmule-crypto` crate so `bitmule-client-wasm`
//! can use the same primitives. This module is now a thin re-export;
//! see `crates/bitmule-crypto/src/lib.rs` for the actual definitions.

pub use bitmule_crypto::*;
