//! Egress metering.
//!
//! Bytes are counted where they leave the process: the body stream that serves
//! a file wraps itself in a [`MeterSink`], so the number is what the socket
//! actually took, not the `Content-Length` the response promised. A viewer
//! that closes a tab mid-range is not billed for the rest of the range.
//!
//! Three properties matter, and they pull against each other:
//!
//! * **Cheap.** A 4 GiB download must not take 16 000 lock acquisitions. The
//!   sink accumulates locally and hands over a total every [`COMMIT_AT`] bytes
//!   and once more when the stream is dropped.
//! * **Uncontended.** Rows live in [`SHARDS`] independent maps keyed by the
//!   share id, so two thousand concurrent downloads touch different locks.
//! * **Bounded.** Row identity is (share, kind, day), never the request: a
//!   thousand viewers of one document are one row a day, and the map is
//!   emptied into `usage.tsv` once an hour.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::Stream;
use tokio::io::AsyncWriteExt;

use super::store::now;

/// Bytes a sink accumulates before taking its shard's lock.
const COMMIT_AT: u64 = 1 << 20;
const SHARDS: usize = 32;

/// What the bytes are priced as. §9 gives view egress its own rate, so the
/// column exists from the start even though today every share download is
/// `download`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Download,
    View,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Download => "download",
            Kind::View => "view",
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
struct Key {
    sid: Arc<str>,
    kind: Kind,
    day: u32,
}

#[derive(Default, Clone, Copy)]
struct Count {
    bytes: u64,
    responses: u64,
}

/// One drained row, in the order `usage.tsv` writes it.
pub struct Row {
    pub day: u32,
    pub sid: Arc<str>,
    pub kind: Kind,
    pub bytes: u64,
    pub responses: u64,
}

pub struct Meter {
    shards: Box<[Mutex<HashMap<Key, Count>>]>,
}

fn shard_of(sid: &str) -> usize {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in sid.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (h % SHARDS as u64) as usize
}

impl Default for Meter {
    fn default() -> Self {
        Self::new()
    }
}

impl Meter {
    pub fn new() -> Self {
        Meter {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    fn add(&self, sid: &Arc<str>, kind: Kind, day: u32, bytes: u64, responses: u64) {
        if bytes == 0 && responses == 0 {
            return;
        }
        let mut shard = self.shards[shard_of(sid)]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let row = shard.entry(Key { sid: sid.clone(), kind, day }).or_default();
        row.bytes += bytes;
        row.responses += responses;
    }

    /// A sink for one response body. Counts as the body is read; commits the
    /// residue when dropped.
    pub fn sink(self: &Arc<Self>, sid: &str, kind: Kind) -> MeterSink {
        MeterSink {
            meter: self.clone(),
            sid: Arc::from(sid),
            kind,
            pending: 0,
            responses: 0,
        }
    }

    /// Empty every shard. The caller writes the rows; on failure it can hand
    /// them back with [`Meter::restore`].
    pub fn take(&self) -> Vec<Row> {
        let mut out = Vec::new();
        for shard in self.shards.iter() {
            let mut map = shard.lock().unwrap_or_else(|e| e.into_inner());
            if map.is_empty() {
                continue;
            }
            out.reserve(map.len());
            for (key, count) in map.drain() {
                out.push(Row {
                    day: key.day,
                    sid: key.sid,
                    kind: key.kind,
                    bytes: count.bytes,
                    responses: count.responses,
                });
            }
        }
        out
    }

    fn restore(&self, rows: Vec<Row>) {
        for row in rows {
            self.add(&row.sid, row.kind, row.day, row.bytes, row.responses);
        }
    }

    /// Append the drained rows to `path`. Returns how many were written.
    pub async fn flush(&self, path: &Path) -> io::Result<usize> {
        let rows = self.take();
        if rows.is_empty() {
            return Ok(0);
        }
        let mut out = String::with_capacity(rows.len() * 48);
        for row in &rows {
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\n",
                row.day,
                row.kind.as_str(),
                row.sid,
                row.bytes,
                row.responses
            ));
        }
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        let written: io::Result<()> = async {
            let mut f = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;
            f.write_all(out.as_bytes()).await?;
            f.flush().await
        }
        .await;
        match written {
            Ok(()) => Ok(rows.len()),
            Err(e) => {
                // Do not lose a day of billing to one bad write.
                self.restore(rows);
                Err(e)
            }
        }
    }

    /// Flush hourly, forever. The owner's call: no per-request writes, and an
    /// hour of loss on a hard crash is fine.
    pub fn spawn_flush(self: &Arc<Self>, path: PathBuf, period: Duration) {
        let meter = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.tick().await; // the first tick fires immediately; the meter is empty
            loop {
                tick.tick().await;
                match meter.flush(&path).await {
                    Ok(0) => {}
                    Ok(n) => tracing::debug!(rows = n, path = %path.display(), "egress meter flushed"),
                    Err(e) => tracing::warn!(error = %e, path = %path.display(), "egress meter flush failed"),
                }
            }
        });
    }
}

/// The per-body counter. One of these travels with a response stream.
pub struct MeterSink {
    meter: Arc<Meter>,
    sid: Arc<str>,
    kind: Kind,
    pending: u64,
    responses: u64,
}

impl MeterSink {
    fn add(&mut self, bytes: u64) {
        if self.responses == 0 {
            self.responses = 1;
        }
        self.pending += bytes;
        if self.pending >= COMMIT_AT {
            self.commit();
        }
    }

    fn commit(&mut self) {
        if self.pending == 0 && self.responses == 0 {
            return;
        }
        let day = (now() / 86_400) as u32;
        self.meter
            .add(&self.sid, self.kind, day, self.pending, self.responses);
        self.pending = 0;
        self.responses = 0;
    }
}

impl Drop for MeterSink {
    fn drop(&mut self) {
        self.commit();
    }
}

/// A body stream that bills what it hands upstream.
pub struct Metered {
    inner: Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>>,
    sink: MeterSink,
}

pub fn metered<S>(inner: S, sink: MeterSink) -> Metered
where
    S: Stream<Item = Result<Bytes, io::Error>> + Send + 'static,
{
    Metered {
        inner: Box::pin(inner),
        sink,
    }
}

impl Stream for Metered {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                this.sink.add(chunk.len() as u64);
                Poll::Ready(Some(Ok(chunk)))
            }
            other => other,
        }
    }
}
