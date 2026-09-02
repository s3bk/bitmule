//! Shared helpers for the e2e tests: server auto-start, webdriver auto-start,
//! random-file generation, sha256 verification.

use anyhow::{anyhow, bail, Context, Result};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
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
}

impl Env {
    /// Bring up whatever the tests need. Env vars can override each piece:
    /// - BITMULE_SERVER (e.g. `http://127.0.0.1:8443`) — skip auto-start of
    ///   bitmule-server if already running externally.
    /// - BITMULE_WEBDRIVER (e.g. `http://127.0.0.1:9515`) — skip auto-start
    ///   of chromedriver.
    pub async fn bring_up() -> Result<Self> {
        let (server_url, server_child) = match std::env::var("BITMULE_SERVER").ok() {
            Some(url) => (url, None),
            None => {
                let child = spawn_server(DEFAULT_SERVER_ADDR).await?;
                (format!("http://{}", DEFAULT_SERVER_ADDR), Some(child))
            }
        };

        let (webdriver_url, webdriver_child) = match std::env::var("BITMULE_WEBDRIVER").ok() {
            Some(url) => (url, None),
            None => {
                let child = spawn_chromedriver(9515).await?;
                (DEFAULT_WEBDRIVER_URL.to_string(), Some(child))
            }
        };

        Ok(Env {
            server_url,
            webdriver_url,
            _webdriver: webdriver_child,
            _server: server_child,
        })
    }
}

async fn spawn_server(bind: &str) -> Result<Child> {
    // Build+run against the workspace binary. `cargo run -p bitmule-server`
    // is the portable form that works from any CWD when this test is run
    // via `cargo test -p bitmule-e2e-tests`.
    let mut cmd = Command::new(env!("CARGO"));
    cmd.args([
        "run", "--quiet", "-p", "bitmule-server", "--",
        "--bind", bind,
    ])
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

/// Run the CLI as a subprocess with the given args. Waits for completion
/// and returns (exit-status, stdout).
pub async fn run_cli(server_url: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<(std::process::ExitStatus, String)> {
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
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = cmd.spawn().context("spawn bitmule cli")?;
    if let Some(data) = stdin {
        use tokio::io::AsyncWriteExt;
        child.stdin.as_mut().unwrap().write_all(data).await?;
    }
    let out = child.wait_with_output().await?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    Ok((out.status, stdout))
}

/// Extract the 64-char session hex from `bitmule recv --server ...` stdout.
/// The CLI prints a share link like `<server>/#<hex>` when it generates
/// a fresh session.
pub fn extract_session_hex(cli_output: &str) -> Result<String> {
    for line in cli_output.lines() {
        if let Some(hash) = line.split_once('#').map(|(_, h)| h.trim()) {
            if hash.len() >= 64 {
                let hex = &hash[..64];
                if hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Ok(hex.to_string());
                }
            }
        }
    }
    Err(anyhow!("no session hex in CLI output:\n{cli_output}"))
}
