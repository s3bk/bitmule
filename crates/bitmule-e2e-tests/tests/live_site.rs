//! The live site as a browser sees it: the pages `mul.li` and `bitmule.net`
//! serve, a real Chromium, and a sender that is an app session (the CLI here,
//! the Qt client on the owner's desktop — same protocol).
//!
//! This is the half of the system the other suites do not touch. transport_matrix
//! and transfer.rs run against `bitmule-server`, whose receiver is the CLI or
//! `web/test/page.html`; the links people actually open are served by
//! `bitmule-proto`, and the browser receive goes through `web/live.js` and the
//! wasm session. Every failure the owner has reported by hand — "the sender is
//! not online", a transfer that is "listed as stopped" — lives in that half, so
//! it gets a suite of its own.
//!
//! What is needed to run it:
//!   - `bitmule-proto`, built: `cargo build --release` in ../bitmule-proto.
//!     Override with BITMULE_PROTO_BIN, the docroot with BITMULE_PROTO_WEB.
//!   - node and playwright-core with a Chromium: BITMULE_PLAYWRIGHT names the
//!     module directory, BITMULE_CHROME the browser binary. Without them the
//!     browser cases are skipped (BITMULE_REQUIRE_BROWSER=1 makes that a failure).
//!   - the CLI, as the other e2e suites find it (BITMULE_CLI, else target/…).
//!
//!     cargo test -p bitmule-e2e-tests --test live_site -- --nocapture
//!
//! Each case starts its own pair of processes on free loopback ports: the site
//! (`bitmule-proto`, the pages) and the room (`bitmule-server`, the websocket
//! and the relay), served over plain http. That is why `bitmule-proto` grew a
//! `--host` that may carry its scheme — the page's
//! `<meta name="bitmule-room">` then points at `ws://127.0.0.1:PORT` instead of
//! an https origin that is not there.

mod common;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use common::*;
use serde_json::Value;
use tokio::process::{Child, Command};

const PAGE_TIMEOUT: Duration = Duration::from_secs(120);

/// The prototype the live site is served by, and its docroot. Both may be
/// named, because the site and this suite are separate trees.
fn proto_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("BITMULE_PROTO_BIN") {
        return Some(PathBuf::from(p)).filter(|p| p.is_file());
    }
    let dir = std::env::var("BITMULE_PROTO_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/home/hematite/bitmule-proto"));
    ["release", "debug"]
        .iter()
        .map(|profile| dir.join("target").join(profile).join("bitmule-proto"))
        .find(|p| p.is_file())
}

fn proto_web() -> PathBuf {
    std::env::var("BITMULE_PROTO_WEB")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/home/hematite/bitmule-proto/web"))
}

/// A child process killed when the test lets go of it, whatever the exit path.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

/// The site is two processes, as the deployment is: `bitmule-proto` serves the
/// pages (`mul.li`), and `bitmule-server` carries the room, the websocket and
/// the relay (`bitmule.net`). The page is told which origin its room is on, the
/// way `--host` tells it in production.
struct Site {
    /// Where the pages are: the link is opened here.
    url: String,
    /// Where the room is: the sender joins it, and so does the page.
    room: String,
    _data: Scratch,
    _child: Proc,
}

impl Site {
    async fn start(room: &str) -> Result<Site> {
        let Some(bin) = proto_bin() else {
            bail!(
                "no bitmule-proto binary: build it (cargo build --release in bitmule-proto), \
                 or set BITMULE_PROTO_BIN"
            );
        };
        let web = proto_web();
        if !web.join("d.html").is_file() {
            bail!("no docroot at {}: set BITMULE_PROTO_WEB", web.display());
        }
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0")?;
            l.local_addr()?.port()
        };
        let addr = format!("127.0.0.1:{port}");
        let url = format!("http://{addr}");
        let data = Scratch::new("site")?;
        let child = Command::new(&bin)
            .arg("--addr").arg(&addr)
            // No TLS on loopback, so the room's scheme is named and the pages
            // point their websocket at ws:// (main.rs room_origin).
            .arg("--host").arg(room)
            .arg("--short-host").arg(&addr)
            .arg("--web").arg(&web)
            .arg("--data").arg(data.path())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("spawn {}", bin.display()))?;
        let mut child = Proc(child);

        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if std::net::TcpStream::connect_timeout(
                &addr.parse()?, Duration::from_millis(200)).is_ok() {
                return Ok(Site { url, room: room.to_string(), _data: data, _child: child });
            }
            if let Ok(Some(status)) = child.0.try_wait() {
                bail!("bitmule-proto exited at once: {status}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        bail!("bitmule-proto never listened on {addr}");
    }
}

/// Whether the page half of the suite can run: node, playwright-core, Chromium.
fn page_harness() -> Result<bool> {
    let node = Path::new("/usr/bin/node");
    if !node.is_file() {
        return skip("browser", "no node at /usr/bin/node");
    }
    let core = std::env::var("BITMULE_PLAYWRIGHT").unwrap_or_else(|_| {
        "/home/hematite/IBA/FYP/Kenna/agent/node_modules/playwright-core".to_string()
    });
    if !Path::new(&core).join("index.js").is_file() {
        return skip("browser", &format!("no playwright-core at {core} (set BITMULE_PLAYWRIGHT)"));
    }
    let chrome = std::env::var("BITMULE_CHROME").unwrap_or_else(|_| {
        format!("{}/.cache/ms-playwright/chromium-1148/chrome-linux/chrome",
                std::env::var("HOME").unwrap_or_default())
    });
    if !Path::new(&chrome).is_file() {
        return skip("browser", &format!("no Chromium at {chrome} (set BITMULE_CHROME)"));
    }
    Ok(true)
}

/// `Ok(false)` is "skip", and BITMULE_REQUIRE_BROWSER turns it into a failure —
/// the same contract the other suites have (common::need_browser).
fn skip(case: &str, why: &str) -> Result<bool> {
    if std::env::var_os("BITMULE_REQUIRE_BROWSER").is_some() {
        bail!("{case} cannot run and BITMULE_REQUIRE_BROWSER is set: {why}");
    }
    eprintln!("[e2e] skipping {case}: {why}");
    Ok(false)
}

/// One browser, one link. The script presses the page's own button and reports
/// what the page said; `expect` is "ok" or "offline".
async fn open_in_browser(url: &str, expect: &str, download: Option<&Path>) -> Result<Value> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/live_page.mjs");
    let mut cmd = Command::new("/usr/bin/node");
    cmd.arg(&script).arg("--url").arg(url).arg("--expect").arg(expect)
        .arg("--timeout").arg(PAGE_TIMEOUT.as_millis().to_string());
    if let Some(dir) = download {
        cmd.arg("--download").arg(dir);
    }
    let out = tokio::time::timeout(PAGE_TIMEOUT + Duration::from_secs(30), cmd.output())
        .await
        .context("the browser script hung")?
        .context("run the browser script")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().rev().find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| anyhow!(
            "the browser script printed no report (exit {:?})\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
            out.status.code(), String::from_utf8_lossy(&out.stderr)))?;
    let report: Value = serde_json::from_str(line).context("parse the browser report")?;
    if !out.status.success() {
        bail!(
            "the page did not do what was asked (wanted {expect}): {}\n--- page said ---\n{}",
            report, report["text"].as_str().unwrap_or("")
        );
    }
    Ok(report)
}

/// The two origins of the deployment, plus the browser check: `Ok(None)` means
/// "no browser here, skip".
async fn harness() -> Result<Option<(Env, Site)>> {
    if !page_harness()? {
        return Ok(None);
    }
    let room = Env::bring_up_server_only().await?;
    let site = Site::start(&room.server_url).await?;
    Ok(Some((room, site)))
}

/// the Qt client shares: the same link keeps answering while the app runs.
async fn spawn_sender(site: &Site, file: &Path) -> Result<(Cli, String)> {
    let mut sender = spawn_cli_with_stderr(
        &site.room,
        &["send", "--multi", file.to_str().unwrap()],
        true,
    )?;
    let share = match read_stdout_for_share(&mut sender, Duration::from_secs(30)).await {
        Ok(s) => s,
        Err(e) => {
            let se = drain_stderr(&mut sender).await;
            bail!("no share URL from the sender: {e:#}\n--- sender stderr ---\n{}", se.trim_end());
        }
    };
    // `<origin>/#<code>` → the link as the page wants it. The fragment is the
    // code alone; the path `/d` is the viewer the link is opened in.
    let code = share.rsplit_once('#')
        .map(|(_, c)| c.trim().to_string())
        .ok_or_else(|| anyhow!("the sender printed a link with no key: {share}"))?;
    Ok((sender, format!("{}/d#{}", site.url, code)))
}

/// The whole point: a link the app printed is opened in a browser and the bytes
/// arrive, whole and correct.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_live_link_is_received_in_the_browser() -> Result<()> {
    let Some((_room, site)) = harness().await? else { return Ok(()) };
    let src = Scratch::new("files")?;
    let dst = Scratch::new("files")?;
    let (file, want) = make_random_file(src.path(), random_size_bytes())?;

    let (_sender, link) = spawn_sender(&site, &file).await?;
    eprintln!("[e2e] opening {link}");
    let report = open_in_browser(&link, "ok", Some(dst.path())).await?;

    let saved = report["saved"].as_str().ok_or_else(|| anyhow!("nothing was saved: {report}"))?;
    assert_eq!(sha256_file(Path::new(saved))?, want, "the bytes that arrived are not the bytes sent");
    assert!(report["text"].as_str().unwrap_or("").contains("checksum holds"), "{report}");
    Ok(())
}

/// A share answers more than one browser. This was a real regression: the
/// sender returned as soon as its first receiver finished, and the next person
/// to open the same link was told the sender was not online.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_live_share_answers_a_second_browser() -> Result<()> {
    let Some((_room, site)) = harness().await? else { return Ok(()) };
    let src = Scratch::new("files")?;
    let (file, want) = make_random_file(src.path(), random_size_bytes())?;

    let (_sender, link) = spawn_sender(&site, &file).await?;
    for who in ["first", "second"] {
        let dst = Scratch::new("files")?;
        let report = open_in_browser(&link, "ok", Some(dst.path())).await
            .with_context(|| format!("{who} browser"))?;
        let saved = report["saved"].as_str().ok_or_else(|| anyhow!("{who}: nothing saved: {report}"))?;
        assert_eq!(sha256_file(Path::new(saved))?, want, "{who} browser got other bytes");
    }
    Ok(())
}

/// And when the sender really is gone, the page says so — in the words the
/// owner was quoted, not by spinning forever and not with a generic failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_live_link_says_the_sender_is_gone() -> Result<()> {
    let Some((_room, site)) = harness().await? else { return Ok(()) };
    let src = Scratch::new("files")?;
    let (file, _want) = make_random_file(src.path(), random_size_bytes())?;

    let (sender, link) = spawn_sender(&site, &file).await?;
    drop(sender); // SIGKILL to the whole group: the room goes with it
    tokio::time::sleep(Duration::from_millis(500)).await;

    let report = open_in_browser(&link, "offline", None).await?;
    let text = report["text"].as_str().unwrap_or("");
    assert!(text.contains("not online"), "the page did not say the sender was gone: {report}");
    Ok(())
}
