//! Shared helpers for the e2e tests: server auto-start, webdriver auto-start,
//! random-file generation, sha256 verification.

use anyhow::{anyhow, bail, Context, Result};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use std::{
    net::TcpStream,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::process::{Child, Command};

/// Where the bitmule-server ends up listening if the test starts it itself.
/// Callers should read [`Env::server_url`] rather than hardcoding — an env
/// override lets a locally-running server be reused across test runs.
pub const DEFAULT_SERVER_ADDR: &str = "127.0.0.1:8443";

/// The webdriver endpoint thirtyfour talks to. If BITMULE_WEBDRIVER is unset
/// the test suite starts chromedriver on this port.
pub const DEFAULT_WEBDRIVER_URL: &str = "http://127.0.0.1:9515";

pub struct Env {
    pub server_url: String,
    pub webdriver_url: String,
    // Child processes we spawned — dropped => killed on test end. Order
    // matters for graceful shutdown: webdriver first, then the server.
    pub _webdriver: Option<Child>,
    pub _server: Option<Child>,
    pub _data_dir: TempDir,
}

impl Env {
    /// Bring up whatever the tests need. Env vars can override each piece:
    /// - BITMULE_SERVER (e.g. `http://127.0.0.1:8443`) — skip auto-start of
    ///   bitmule-server if already running externally.
    /// - BITMULE_WEBDRIVER (e.g. `http://127.0.0.1:9515`) — skip auto-start
    ///   of chromedriver.
    pub async fn bring_up() -> Result<Self> {
        let web_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../web");
        let data_dir = TempDir::new()?;
        let (server_url, server_child) = match std::env::var("BITMULE_SERVER").ok() {
            Some(url) => (url, None),
            None => {
                let child = spawn_server(DEFAULT_SERVER_ADDR, data_dir.path(), &web_dir).await.context("spawn_server")?;
                (format!("http://{}", DEFAULT_SERVER_ADDR), Some(child))
            }
        };

        let (webdriver_url, webdriver_child) = match std::env::var("BITMULE_WEBDRIVER").ok() {
            Some(url) => (url, None),
            None => {
                let child = spawn_chromedriver(9515).await.context("spawn_chromedriver")?;
                (DEFAULT_WEBDRIVER_URL.to_string(), Some(child))
            }
        };

        Ok(Env {
            server_url,
            webdriver_url,
            _webdriver: webdriver_child,
            _server: server_child,
            _data_dir: data_dir
        })
    }

    /// Server-only variant for tests that don't need a browser
    /// (transport_matrix, CLI-only smoke tests). Skips chromedriver
    /// spawn so a box without chromedriver installed can still run
    /// the CLI-only matrix. `webdriver_url` is populated with the
    /// default sentinel string but MUST NOT be used.
    /// Kenna 2026-09-13.
    pub async fn bring_up_server_only() -> Result<Self> {
        let web_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../web");
        let data_dir = TempDir::new()?;
        let (server_url, server_child) = match std::env::var("BITMULE_SERVER").ok() {
            Some(url) => (url, None),
            None => {
                let child = spawn_server(DEFAULT_SERVER_ADDR, data_dir.path(), &web_dir).await.context("spawn_server")?;
                (format!("http://{}", DEFAULT_SERVER_ADDR), Some(child))
            }
        };
        Ok(Env {
            server_url,
            webdriver_url: DEFAULT_WEBDRIVER_URL.to_string(),
            _webdriver: None,
            _server: server_child,
            _data_dir: data_dir,
        })
    }
}

async fn spawn_server(bind: &str, data_dir: &Path, web_dir: &Path) -> Result<Child> {
    // Build+run against the workspace binary. `cargo run -p bitmule-server`
    // is the portable form that works from any CWD when this test is run
    // via `cargo test -p bitmule-e2e-tests`.
    let mut cmd = Command::new(env!("CARGO"));
    cmd.args([
        "run", "--quiet", "-p", "bitmule-server", "--",
        "--bind", bind,
        "--data-dir"
    ]).arg(data_dir)
    .arg("--web-dir")
    .arg(web_dir)
    .stdout(Stdio::null())
    .stderr(Stdio::inherit())
    .kill_on_drop(true);
    let child = cmd.spawn().context("spawn bitmule-server")?;
    wait_for_tcp(bind, Duration::from_secs(30)).await?;
    Ok(child)
}

async fn spawn_chromedriver(port: u16) -> Result<Child> {
    let bin = std::env::var("BITMULE_CHROMEDRIVER").unwrap_or_else(|_| "chromedriver".into());
    let mut cmd = Command::new(&bin);
    cmd.arg(format!("--port={port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let child = cmd.spawn()
        .with_context(|| format!("spawn {bin} — install chromedriver or set BITMULE_CHROMEDRIVER"))?;
    let addr = format!("127.0.0.1:{port}");
    wait_for_tcp(&addr, Duration::from_secs(10)).await?;
    Ok(child)
}

async fn wait_for_tcp(addr: &str, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr.parse()?, Duration::from_millis(200)).is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    bail!("nothing listening on {addr} after {timeout:?}")
}

/// Size formula per Seb 2026-09-02: `(1 + rand()) * 2^n` KiB with n ∈ [4, 7].
/// Produces files in the 16 KiB – 256 KiB range for round-trip smoke tests.
pub fn random_size_bytes() -> usize {
    let mut rng = rand::thread_rng();
    let n: u32 = rng.gen_range(4..=7);
    let scale: f64 = 1.0 + rng.gen::<f64>();
    (scale * (1u64 << n) as f64 * 1024.0) as usize
}

/// Write `n` random bytes to a temp file, return its path + sha256.
pub fn make_random_file(dir: &Path, n: usize) -> Result<(PathBuf, [u8; 32])> {
    let mut rng = rand::thread_rng();
    let mut buf = vec![0u8; n];
    rng.fill_bytes(&mut buf);
    let hash: [u8; 32] = Sha256::digest(&buf).into();
    let hex = hex_short(&hash);
    let path = dir.join(format!("send-{hex}.bin"));
    std::fs::write(&path, &buf).with_context(|| format!("write {}", path.display()))?;
    Ok((path, hash))
}

pub fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(Sha256::digest(&bytes).into())
}

fn hex_short(hash: &[u8; 32]) -> String {
    hash.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// Locate the cargo-built bitmule CLI binary. Prefers a debug build; falls
/// back to `cargo run`. Set BITMULE_CLI to override.
pub fn cli_bin() -> String {
    if let Ok(p) = std::env::var("BITMULE_CLI") { return p; }
    // Assume `cargo test -p bitmule-e2e-tests` has already built the workspace.
    let manifest = env!("CARGO_MANIFEST_DIR");
    let candidate = PathBuf::from(manifest).join("../../target/debug/bitmule");
    if candidate.exists() { return candidate.to_string_lossy().into_owned(); }
    "cargo".into() // caller handles the `run -p bitmule --` prefix
}

/// Spawn the CLI as a subprocess with piped stdout. Caller reads stdout
/// (typically to capture the share URL that send/recv print on start-up
/// before blocking on the transfer) and then awaits the child.
pub fn spawn_cli(server_url: &str, args: &[&str]) -> Result<Child> {
    let bin = cli_bin();
    let (program, prefix): (&str, Vec<&str>) = if bin.ends_with("cargo") || bin == "cargo" {
        ("cargo", vec!["run", "--quiet", "-p", "bitmule", "--"])
    } else {
        (bin.as_str(), vec![])
    };
    let mut cmd = Command::new(program);
    cmd.args(&prefix)
        .arg("--server").arg(server_url)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    cmd.spawn().context("spawn bitmule cli")
}

/// Read lines from a child's stdout until one contains a URL with a `#<hex>`
/// fragment (matches both `<server>/#<hex>` and `<server>/send#<hex>` per
/// Seb 2026-09-02: SPA modes 2 and 3). Returns the 64-char hex on the
/// first match, or times out after `timeout`.
pub async fn read_stdout_for_hex(child: &mut Child, timeout: Duration) -> Result<String> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("no piped stdout"))?;
    let mut reader = BufReader::new(stdout).lines();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, reader.next_line()).await {
            Ok(Ok(Some(line))) => {
                if let Some((_, hash)) = line.split_once('#') {
                    let hex: String = hash.chars().take(64).collect();
                    if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                        // Put the reader back so subsequent stdout drains don't stall
                        // the child (bounded stdout pipe buffer would otherwise
                        // block send/recv once full). We spawn a background task
                        // to consume the rest.
                        let mut lines = reader;
                        tokio::spawn(async move {
                            while let Ok(Some(_)) = lines.next_line().await {}
                        });
                        return Ok(hex);
                    }
                }
            }
            Ok(Ok(None)) => bail!("CLI stdout closed before printing a session URL"),
            Ok(Err(e)) => bail!("CLI stdout read: {e}"),
            Err(_) => bail!("timed out waiting for session URL on CLI stdout"),
        }
    }
}
