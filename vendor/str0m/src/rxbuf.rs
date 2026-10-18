//! Buffers for what arrives over the data channel, from slab pools: the
//! decrypted packet is handed to SCTP as `Bytes` of the same memory, and a
//! message merged from its chunks (`Delivery::Merged`) is one slab buffer.

use std::sync::{Arc, OnceLock};

use bitmule_buf::Pool;

/// A decrypted SCTP packet (a DTLS record is at most an MTU).
pub(crate) const PACKET: usize = 2048;
/// A merged message; larger ones get a buffer of their own.
pub(crate) const MESSAGE: usize = 17 * 1024;

pub(crate) fn packets() -> &'static Arc<Pool<PACKET>> {
    static POOL: OnceLock<Arc<Pool<PACKET>>> = OnceLock::new();
    POOL.get_or_init(|| Pool::slab(2048))
}

pub(crate) fn messages() -> &'static Arc<Pool<MESSAGE>> {
    static POOL: OnceLock<Arc<Pool<MESSAGE>>> = OnceLock::new();
    POOL.get_or_init(|| Pool::slab(256))
}
