// The macro — the key fix is `static SITE: AwaitSite` (owned, not a reference to a temporary)

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::sync::atomic::{AtomicU64, Ordering};

use linkme::distributed_slice;

#[macro_export]
macro_rules! tracked_await {
    ($expr:expr, $labl:literal) => {{
        // Declare SITE as an owned static item, not a reference to a temporary.
        // AwaitSite::new() is const fn so this is valid.
        static SITE: $crate::await_tracker::AwaitSite =
            $crate::await_tracker::AwaitSite::new(concat!(file!(), ":", line!()), $labl);

        // Register &SITE into the distributed slice.
        // This is a separate static holding the pointer — no interior mutability here.
        #[linkme::distributed_slice($crate::await_tracker::AWAIT_SITES)]
        static SITE_REF: &$crate::await_tracker::AwaitSite = &SITE;

        $crate::await_tracker::TrackedFuture::new($expr, &SITE).await
    }};

    ($expr:expr) => (tracked_await!($expr, ""))
}

pub struct AwaitSite {
    pub location: &'static str,
    pub label: &'static str,
    pub immediate: AtomicU64,
    pub blocked: AtomicU64,
}

// AtomicU64::new is a const fn, so this is valid in const context
impl AwaitSite {
    pub const fn new(location: &'static str, label: &'static str) -> Self {
        Self {
            location,
            label,
            immediate: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
        }
    }
}

#[distributed_slice]
pub static AWAIT_SITES: [&'static AwaitSite];

pub struct TrackedFuture<F: Future> {
    inner: Pin<Box<F>>,
    site: &'static AwaitSite,
    ever_pending: bool,
}

impl<F: Future> TrackedFuture<F> {
    pub fn new(inner: F, site: &'static AwaitSite) -> Self {
        Self { inner: Box::pin(inner), site, ever_pending: false }
    }
}

impl<F: Future> Future for TrackedFuture<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.inner.as_mut().poll(cx) {
            Poll::Ready(val) => {
                if self.ever_pending {
                    self.site.blocked.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.site.immediate.fetch_add(1, Ordering::Relaxed);
                }
                Poll::Ready(val)
            }
            Poll::Pending => {
                self.ever_pending = true;
                Poll::Pending
            }
        }
    }
}
// src/await_tracker.rs — print_report, unchanged
pub fn print_report() {
    let sites: Vec<&&AwaitSite> = AWAIT_SITES.iter().collect();
    if sites.is_empty() {
        println!("[await-tracker] No awaits recorded.");
        return;
    }

    // Group by file (the part before the last ':')
    let mut by_file: std::collections::BTreeMap<&str, Vec<&&AwaitSite>> =
        std::collections::BTreeMap::new();

    for site in &sites {
        // location is "src/foo.rs:42" — split off the line number
        let file = site.location.rsplitn(2, ':').nth(1).unwrap_or(site.location);
        by_file.entry(file).or_default().push(site);
    }

    // Within each file, sort by line number
    for sites in by_file.values_mut() {
        sites.sort_by_key(|s| {
            s.location
                .rsplitn(2, ':')
                .next()
                .and_then(|n| n.parse::<u32>().ok())
                .unwrap_or(0)
        });
    }

    println!();
    println!("await-tracker report");


    for (file, sites) in &by_file {
        println!();
        println!("  {}", file);
        println!("   {:>4}  {:<32}  {:>7}  {:>7}  {:>9}", "line", "label", "immed", "blocked", "% blocked");

        for site in sites {
            let line = site.location.rsplitn(2, ':').next().unwrap_or("?");
            let imm  = site.immediate.load(Ordering::Relaxed);
            let blk  = site.blocked.load(Ordering::Relaxed);
            println!(
                "   {:>4}  {:<32}  {:>7}  {:>7}  {:>8.0}%",
                line, site.label, imm, blk, 100. * blk as f64 / (blk + imm) as f64
            );
        }

    }
}
