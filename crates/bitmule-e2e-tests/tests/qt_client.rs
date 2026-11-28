//! The Qt client, as a program: a window that shares a file and a window that
//! fetches a link, against the same `bitmule-server` the other suites use.
//!
//! Every failure the owner has reported from his desktop was in this half — the
//! window that says "Preparing…" forever, the send that is listed as stopped,
//! the link that does not open — and no suite ran the client he runs. This one
//! does: the real binary, headless, with the two things a person does by hand
//! named in the environment instead of clicked (`init_automation` in
//! crates/bitmule-qt6/src/main.rs):
//!
//!   - `BITMULE_QT_SHARE=<path>`: drop that path and press Share at startup;
//!   - `BITMULE_QT_RECV=<link>`: paste that link and fetch it at startup.
//!
//! The window writes what it does on stderr (`share: link …`, `recv: complete —
//! <name> <path>`), and the suite follows those lines and kills it when the
//! case is done — no exit hook in the app, and no click anywhere.
//!
//! The window is started on Qt's offscreen platform with the software QML
//! backend, so no display and no GPU are needed. Its `HOME` and XDG dirs are a
//! scratch tree: downloads land in `<home>/downloads/bitmule`, and the owner's
//! own configuration, keyring and download folder are never touched.
//!
//! What is needed to run it: the client, built (`cargo build -p bitmule-qt6`,
//! or `BITMULE_QT` naming the binary), and the CLI the other suites find. The
//! cases skip — not fail — when the client is not built.
//!
//!     cargo test -p bitmule-e2e-tests --test qt_client -- --nocapture

mod common;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use common::*;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

/// One wait. A relay transfer on loopback is seconds; the proof of work and the
/// session come next, and a hash of a small file is nothing.
const WAIT: Duration = Duration::from_secs(120);

/// The Qt client's binary: `BITMULE_QT`, else a cargo build in target/. `None`
/// is "not built here", which skips the cases rather than failing them.
fn qt_bin() -> Option<PathBuf> {
    bin_path("bitmule-qt6", "BITMULE_QT")
}

fn need_qt() -> Result<Option<PathBuf>> {
    match qt_bin() {
        Some(p) => Ok(Some(p)),
        None => {
            if std::env::var_os("BITMULE_REQUIRE_QT").is_some() {
                bail!(
                    "no bitmule-qt6 binary and BITMULE_REQUIRE_QT is set: \
                     build it with `cargo build -p bitmule-qt6`, or set BITMULE_QT"
                );
            }
            eprintln!(
                "[e2e] skipping the Qt client: no bitmule-qt6 binary (build it with \
                 `cargo build -p bitmule-qt6`, or set BITMULE_QT)"
            );
            Ok(None)
        }
    }
}

/// The window, headless. Qt's offscreen platform draws nothing, and
/// `QT_QUICK_BACKEND=software` keeps it off a GPU a test box may not have.
///
/// What it says goes to stderr, line by line, exactly what a run from a terminal
/// shows — that is both how the suite follows it and what a failure prints.
struct QtApp {
    child: GroupChild,
    lines: Arc<Mutex<Vec<String>>>,
    /// `HOME` and the XDG dirs this window was given. Its downloads land in
    /// `<home>/downloads/bitmule`; nothing of the owner's is touched.
    home: Scratch,
}

impl QtApp {
    /// Start the client with `vars` on top of the harness's own environment.
    /// `server_url` is the suite's loopback server: the window shares through
    /// it (`BITMULE_SERVER`), may name its host in a link (`BITMULE_QT_HOSTS`)
    /// and may use plain http for it (`BITMULE_INSECURE`).
    fn start(qt: &Path, server_url: &str, vars: &[(&str, &str)]) -> Result<QtApp> {
        let home = Scratch::new("qt-home")?;
        let runtime = home.path().join("run");
        std::fs::create_dir_all(&runtime)?;
        #[cfg(unix)]
        {
            // Qt refuses a runtime dir others can read; 0700 is what it wants.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))?;
        }
        // `http://127.0.0.1:PORT` → `127.0.0.1`: the host a link may name.
        let host = server_url
            .split("://").nth(1).unwrap_or("")
            .split(['/', ':']).next().unwrap_or("");

        let mut cmd = Command::new(qt);
        cmd.env("QT_QPA_PLATFORM", "offscreen")
            .env("QT_QUICK_BACKEND", "software")
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env("XDG_CACHE_HOME", home.path().join("cache"))
            .env("XDG_RUNTIME_DIR", &runtime)
            .env("XDG_DOWNLOAD_DIR", home.path().join("downloads"))
            .env("BITMULE_SERVER", server_url)
            .env("BITMULE_INSECURE", "1")
            .env("BITMULE_QT_HOSTS", host)
            // No session bus: the account password (Secret Service) is not
            // part of these cases, and a missing bus must not look like a hang.
            .env_remove("DBUS_SESSION_BUS_ADDRESS")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        for (k, v) in vars {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn().with_context(|| format!("spawn {}", qt.display()))?;
        let lines = Arc::new(Mutex::new(Vec::new()));
        let stderr = child.stderr.take().context("piped stderr")?;
        {
            let lines = lines.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr).lines();
                while let Ok(Some(line)) = reader.next_line().await {
                    eprintln!("[qt] {line}");
                    if let Ok(mut g) = lines.lock() {
                        g.push(line);
                    }
                }
            });
        }
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(async move {
                // Drained so a chatty window can never block on a full pipe.
                let mut reader = BufReader::new(stdout).lines();
                while matches!(reader.next_line().await, Ok(Some(_))) {}
            });
        }
        Ok(QtApp { child: GroupChild::new(child), lines, home })
    }

    /// Wait for a stderr line containing `needle`; return that line.
    async fn wait_for(&self, needle: &str, timeout: Duration) -> Result<String> {
        let deadline = Instant::now() + timeout;
        let mut seen = 0usize;
        loop {
            {
                let g = self.lines.lock().unwrap();
                let rest = g.get(seen..).unwrap_or(&[]);
                if let Some(line) = rest.iter().find(|l| l.contains(needle)) {
                    return Ok(line.clone());
                }
                seen = g.len();
            }
            if Instant::now() >= deadline {
                bail!(
                    "the window never said {needle:?} (waited {timeout:?})\n--- what it said ---\n{}",
                    self.transcript()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The link out of the window's `share: link <url>` line.
    async fn wait_for_link(&self) -> Result<String> {
        let line = self.wait_for("share: link ", WAIT).await?;
        let url = line
            .split_once("share: link ")
            .map(|(_, u)| u.trim().to_string())
            .unwrap_or_default();
        if !url.contains('#') {
            bail!("the window printed no link: {line}");
        }
        Ok(url)
    }

    /// Everything the window has said so far, for a failure message.
    fn transcript(&self) -> String {
        self.lines.lock().map(|g| g.join("\n")).unwrap_or_default()
    }

    /// Wait for the window to report how the download ended: `recv: complete —
    /// <name> <path>` or `recv: error — …`. `BITMULE_QT_RECV` names one link, so
    /// one line is the whole answer.
    async fn wait_for_download(&mut self, timeout: Duration) -> Result<String> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let g = self.lines.lock().unwrap();
                if let Some(line) = g
                    .iter()
                    .find(|l| l.contains("recv: complete") || l.contains("recv: error"))
                {
                    return Ok(line.clone());
                }
            }
            if Instant::now() >= deadline {
                let _ = self.child.start_kill();
                bail!(
                    "the window never finished the download (waited {timeout:?})\n--- what it said ---\n{}",
                    self.transcript()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
/// The only file in a directory (the CLI's `--out`, a download folder).
fn only_file(dir: &Path) -> Result<PathBuf> {
    let files: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    match files.as_slice() {
        [one] if one.is_file() => Ok(one.clone()),
        other => Err(anyhow!("expected one file in {}, got {other:?}", dir.display())),
    }
}

/// Every file under `dir`, by path relative to it: what a folder share arrives
/// as, whatever the unpacking is called.
fn files_under(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, PathBuf)>) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(&path, base, out)?;
            } else if path.is_file() {
                let rel = path.strip_prefix(base)?.to_string_lossy().into_owned();
                out.push((rel, path));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out)?;
    Ok(out)
}

/// The window makes a link; the CLI — the other kind of sender, and a client
/// this case did not touch — receives the bytes it names, whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_qt_client_shares_and_the_cli_receives() -> Result<()> {
    let Some(qt) = need_qt()? else { return Ok(()) };
    let env = Env::bring_up_server_only().await?;
    let src = Scratch::new("files")?;
    let dst = Scratch::new("files")?;
    let (file, want) = make_random_file(src.path(), random_size_bytes())?;

    let app = QtApp::start(&qt, &env.server_url, &[("BITMULE_QT_SHARE", file.to_str().unwrap())])?;
    let link = app.wait_for_link().await.context("the window made no link")?;
    eprintln!("[e2e] the window's link: {link}");

    let mut receiver = spawn_cli(
        &env.server_url,
        &["recv", "--out", dst.path().to_str().unwrap(), &link],
    )?;
    let status = tokio::time::timeout(WAIT, receiver.wait())
        .await
        .with_context(|| format!("the CLI never finished\n--- the window said ---\n{}", app.transcript()))??;
    assert!(
        status.success(),
        "the receiver failed: {status}\n--- the window said ---\n{}",
        app.transcript()
    );
    assert_eq!(
        sha256_file(&only_file(dst.path())?)?,
        want,
        "the bytes that arrived are not the bytes the window sent"
    );
    Ok(())
}

/// The same link, spelled the way a person is handed it and pastes it back:
/// on the frozen short host, which serves pages and no room.
fn as_printed_link(link: &str) -> String {
    let key = link.split_once('#').map(|(_, k)| k).unwrap_or("");
    format!("https://mul.li#{key}")
}

/// A link on the short host names pages, not a room: the receiver that joined
/// `wss://mul.li/ws/join` was refused by the page server, and the proxy in
/// front turned its 404 into a 500 the CLI could only report as "HTTP error:
/// 500 Internal Server Error" — while the session waited on the long host it
/// had been told about (`--server`). This is the CLI half of that rule.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_short_host_link_reaches_the_room_behind_it() -> Result<()> {
    let Some(qt) = need_qt()? else { return Ok(()) };
    let env = Env::bring_up_server_only().await?;
    let src = Scratch::new("files")?;
    let dst = Scratch::new("files")?;
    let (file, want) = make_random_file(src.path(), random_size_bytes())?;

    let app = QtApp::start(&qt, &env.server_url, &[("BITMULE_QT_SHARE", file.to_str().unwrap())])?;
    let link = app.wait_for_link().await.context("the window made no link")?;
    let link = as_printed_link(&link);
    eprintln!("[e2e] the link as printed: {link}");

    let mut receiver = spawn_cli_with_stderr(
        &env.server_url,
        &["recv", "--out", dst.path().to_str().unwrap(), &link],
        true,
    )?;
    let status = tokio::time::timeout(WAIT, receiver.wait()).await??;
    if !status.success() {
        let se = drain_stderr(&mut receiver).await;
        bail!("recv via a short-host link failed\n--- receiver stderr ---\n{}", se.trim_end());
    }
    let saved = only_file(dst.path())?;
    assert_eq!(sha256_file(&saved)?, want);
    Ok(())
}

/// The other half: the window is handed a short-host link and must paste the
/// code into the room it is set up for, not into the page server that served
/// the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_qt_client_receives_via_a_short_host_link() -> Result<()> {
    let Some(qt) = need_qt()? else { return Ok(()) };
    let env = Env::bring_up_server_only().await?;
    let src = Scratch::new("files")?;
    let (file, want) = make_random_file(src.path(), random_size_bytes())?;

    let mut sender = spawn_cli_with_stderr(&env.server_url, &["send", "--multi", file.to_str().unwrap()], true)?;
    let link = match read_stdout_for_share(&mut sender, WAIT).await {
        Ok(l) => l,
        Err(e) => {
            let se = drain_stderr(&mut sender).await;
            bail!("no link from the sender: {e:#}\n--- sender stderr ---\n{}", se.trim_end());
        }
    };
    let link = as_printed_link(&link);

    let mut app = QtApp::start(&qt, &env.server_url, &[("BITMULE_QT_RECV", &link)])?;
    let line = app.wait_for_download(WAIT).await.context("the window did not finish the download")?;
    assert!(line.contains("recv: complete"), "the window did not get the file: {line}\n--- it said ---\n{}", app.transcript());
    let dir = app.home.path().join("downloads/bitmule");
    let saved = only_file(&dir)
        .with_context(|| format!("nothing usable landed in {}\n--- the window said ---\n{}", dir.display(), app.transcript()))?;
    assert_eq!(sha256_file(&saved)?, want);
    Ok(())
}

/// The other direction, and the one the owner does by hand: a link from
/// somewhere else, fetched by the window. The file must land in the download
/// folder the window was given, and the window must say it arrived.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_qt_client_receives_from_the_cli() -> Result<()> {
    let Some(qt) = need_qt()? else { return Ok(()) };
    let env = Env::bring_up_server_only().await?;
    let src = Scratch::new("files")?;
    let (file, want) = make_random_file(src.path(), random_size_bytes())?;

    let mut sender = spawn_cli_with_stderr(
        &env.server_url,
        &["send", "--multi", file.to_str().unwrap()],
        true,
    )?;
    let link = match read_stdout_for_share(&mut sender, WAIT).await {
        Ok(l) => l,
        Err(e) => {
            let se = drain_stderr(&mut sender).await;
            bail!("no link from the sender: {e:#}\n--- sender stderr ---\n{}", se.trim_end());
        }
    };

    let mut app = QtApp::start(&qt, &env.server_url, &[("BITMULE_QT_RECV", &link)])?;
    let line = app
        .wait_for_download(WAIT)
        .await
        .context("the window did not finish the download")?;
    assert!(
        line.contains("recv: complete"),
        "the window did not get the file: {line}\n--- it said ---\n{}",
        app.transcript()
    );

    let dir = app.home.path().join("downloads/bitmule");
    let saved = only_file(&dir)
        .with_context(|| format!("nothing usable landed in {}\n--- the window said ---\n{}", dir.display(), app.transcript()))?;
    assert_eq!(sha256_file(&saved)?, want, "the bytes the window saved are not the bytes sent");
    let said = app.transcript();
    assert!(said.contains("recv: complete"), "the window did not report the download:\n{said}");
    Ok(())
}

/// A folder is the other thing a person drops: it goes as a zip, and what
/// arrives is the folder again — same names, same bytes, one level deeper than
/// the file case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_qt_client_shares_a_folder() -> Result<()> {
    let Some(qt) = need_qt()? else { return Ok(()) };
    let env = Env::bring_up_server_only().await?;
    let src = Scratch::new("files")?;
    let dst = Scratch::new("files")?;

    let bundle = src.path().join("bundle");
    std::fs::create_dir_all(bundle.join("nested"))?;
    let a = bundle.join("alpha.bin");
    let b = bundle.join("nested/beta.bin");
    let (alpha, beta) = (vec![7u8; 4096], vec![9u8; 8192]);
    std::fs::write(&a, &alpha)?;
    std::fs::write(&b, &beta)?;

    let app = QtApp::start(&qt, &env.server_url, &[("BITMULE_QT_SHARE", bundle.to_str().unwrap())])?;
    let link = app.wait_for_link().await.context("the window made no link")?;
    eprintln!("[e2e] the window's folder link: {link}");

    let mut receiver = spawn_cli_with_stderr(
        &env.server_url,
        &["recv", "--out", dst.path().to_str().unwrap(), &link],
        true,
    )?;
    let status = tokio::time::timeout(WAIT, receiver.wait())
        .await
        .with_context(|| format!("the CLI never finished\n--- the window said ---\n{}", app.transcript()))??;
    let rx_said = drain_stderr(&mut receiver).await;
    assert!(
        status.success(),
        "the receiver failed: {status}\n--- the receiver said ---\n{}\n--- the window said ---\n{}",
        rx_said.trim_end(),
        app.transcript()
    );

    let got = files_under(dst.path())?;
    let names: Vec<&str> = got.iter().map(|(rel, _)| rel.as_str()).collect();
    for want_name in ["alpha.bin", "nested/beta.bin"] {
        let (_, path) = got
            .iter()
            .find(|(rel, _)| rel.ends_with(want_name))
            .ok_or_else(|| anyhow!(
                "{want_name} did not arrive; got {names:?}\n--- the receiver said ---\n{}",
                rx_said.trim_end()
            ))?;
        let want = if want_name.ends_with("alpha.bin") { &alpha } else { &beta };
        assert_eq!(&std::fs::read(path)?, want, "{want_name} arrived with other bytes");
    }
    Ok(())
}
