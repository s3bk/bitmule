//! The link surfaces, merged from the prototype (`bitmule-proto`) into the
//! server that already carries signaling and the chunk relay.
//!
//! Three things the prototype proved, now kept here:
//!
//! * **A link ends in ciphertext, not in an account.** `POST /v1/pub/shares`
//!   registers rows and hashes a bearer; uploads arrive with the key's
//!   derived `auth_key`, bytes are stored as they came, and a reader fetches
//!   ranges with the same derived key. The server never holds a key that
//!   decrypts anything it stores.
//! * **Invites are caps, not permissions.** An invite carries a byte cap, a
//!   file cap and a one-time flag; the granter token returned once at creation
//!   is what lists the inbox. No accounts, no cookies.
//! * **Egress is metered, not logged.** One row per (share, kind, day), summed
//!   in memory, written once an hour.
//!
//! What is *not* kept: the prototype's hand-written HTTP/1.1 loop, its
//! tab-separated metadata and its per-request file reads. Axum gives the
//! routing and hyper the framing; the store writes JSON atomically; uploads
//! and downloads stream through one fixed buffer; the meter batches a
//! megabyte at a time into sharded maps.

pub mod api;
pub mod meter;
pub mod store;

pub use api::{router, Api, Config, DEFAULT_MAX_UPLOAD};
pub use meter::{Kind, Meter};
pub use store::{Received, Store};
