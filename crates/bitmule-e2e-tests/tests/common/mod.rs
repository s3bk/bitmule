//! Shared helpers for the e2e tests: server auto-start, webdriver auto-start,
//! random-file generation, sha256 verification.

use anyhow::{anyhow, bail, Context, Result};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    net::TcpStream,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering},
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
    // Child processes we spawned, each in its own process group. Fields drop
    // in declaration order, so the webdriver goes first, then the server, then
    // the data dir — and each [`GroupChild`] kill takes the whole tree, which
    // matters because a `cargo run` fallback puts the real binary one level
    // down. No orphan survives a test that passes, fails or panics.
    pub _webdriver: Option<GroupChild>,
    pub _server: Option<GroupChild>,
    pub _data_dir: Scratch,
}

impl Env {
    /// Bring up whatever the tests need. Env vars can override each piece:
    /// - BITMULE_SERVER (e.g. `http://127.0.0.1:8443`) — skip auto-start of
    ///   bitmule-server if already running externally.
    /// - BITMULE_WEBDRIVER (e.g. `http://127.0.0.1:9515`) — skip auto-start
    ///   of chromedriver.
    pub async fn bring_up() -> Result<Self> {
        let web_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web");
        let data_dir = Scratch::new("server")?;
        let (server_url, server_child) = match std::env::var("BITMULE_SERVER").ok() {
            Some(url) => (url, None),
            None => {
                let addr = free_addr()?;
                let child = spawn_server(&addr, data_dir.path(), &web_dir).await.context("spawn_server")?;
                (format!("http://{addr}"), Some(child))
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
        let web_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web");
        let data_dir = Scratch::new("server")?;
        let (server_url, server_child) = match std::env::var("BITMULE_SERVER").ok() {
            Some(url) => (url, None),
            None => {
                let addr = free_addr()?;
                let child = spawn_server(&addr, data_dir.path(), &web_dir).await.context("spawn_server")?;
                (format!("http://{addr}"), Some(child))
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

/// A temp directory that is removed on every exit path: success, an early
/// `?`, and unwinding from a failed assertion. Removal is retried, because a
/// child that was just killed may still be closing files written into it, and
/// a failure is reported instead of silently leaving the tree behind (which is
/// what `TempDir` does when `remove_dir_all` fails).
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    pub fn new(tag: &str) -> Result<Self> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("bitmule-e2e-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
        Ok(Scratch { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(e) = remove_tree(&self.path) {
            eprintln!("[e2e] left behind {}: {e:#}", self.path.display());
        }
    }
}

/// `remove_dir_all` with a few retries; `Ok(())` once the tree is gone.
/// `NotFound` counts as gone, so Drop is safe to run twice.
pub fn remove_tree(path: &Path) -> Result<()> {
    let mut last: Option<std::io::Error> = None;
    for attempt in 0..5u64 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(50 * (attempt + 1)));
            }
        }
    }
    match last {
        Some(e) => Err(e.into()),
        None => Ok(()),
    }
}

/// SIGKILL a child's whole process group. Children are spawned with
/// `process_group(0)`, i.e. as their own group leader, so `-pid` also reaches
/// the binary that `cargo run` started as its child.
fn kill_group(child: &mut Child) {
    if let Some(pid) = child.id() {
        // Safety: `kill` is async-signal-safe and the pid is our own child.
        #[cfg(unix)]
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL)
        };
    }
    let _ = child.start_kill();
}

/// A built workspace binary, so the test kills exactly the process it started.
/// `override_var` (e.g. BITMULE_CLI) wins; then target/debug, target/release.
pub fn bin_path(name: &str, override_var: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var(override_var) {
        return Some(PathBuf::from(p));
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    // Honour CARGO_TARGET_DIR: with a shared target dir the binaries are not
    // under <workspace>/target, and falling back to `cargo run` there would
    // rebuild (slow) and hand the test a process it cannot kill cleanly.
    let target = match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => root.join("target"),
    };
    ["debug", "release"]
        .iter()
        .map(|profile| target.join(profile).join(name))
        .find(|p| p.is_file())
}

/// A child process in its own process group. Derefs to [`Child`], so callers
/// use it like one. Drop kills the group and reaps it: a test that ends early
/// (an `Err`, a failed assertion, a panic) must not leave a `bitmule send`
/// holding a share open, or a `bitmule-server` writing into a data dir that is
/// about to be removed.
pub struct GroupChild(Child);

/// The CLI child — same guard, named for what it is at the call site.
pub type Cli = GroupChild;

impl Deref for GroupChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}

impl DerefMut for GroupChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for GroupChild {
    fn drop(&mut self) {
        kill_group(&mut self.0);
        // Reap: no zombie, and the child is really gone before the temp dir
        // that it may have been writing into is removed.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match self.0.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }
}

/// Whether a browser can be driven: an explicit webdriver URL, an explicit
/// `chromedriver` path, or `chromedriver` on `PATH`.
pub fn browser_available() -> bool {
    if std::env::var_os("BITMULE_WEBDRIVER").is_some()
        || std::env::var_os("BITMULE_CHROMEDRIVER").is_some()
    {
        return true;
    }
    std::env::var_os("PATH")
        .map(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("chromedriver"))
                .any(|p| p.is_file())
        })
        .unwrap_or(false)
}

/// Guard for the browser-driven cases: `Ok(false)` means "skip, no browser on
/// this box", so a CLI-only machine can still run the suite. Set
/// BITMULE_REQUIRE_BROWSER=1 to turn a missing browser into a failure.
pub fn need_browser(case: &str) -> Result<bool> {
    if browser_available() {
        return Ok(true);
    }
    if std::env::var_os("BITMULE_REQUIRE_BROWSER").is_some() {
        bail!("{case} needs a browser: install chromedriver, or set BITMULE_CHROMEDRIVER / \
               BITMULE_WEBDRIVER (BITMULE_REQUIRE_BROWSER is set, so this is not skipped)");
    }
    eprintln!(
        "[e2e] skipping {case}: no chromedriver on PATH \
         (set BITMULE_CHROMEDRIVER or BITMULE_WEBDRIVER to run it)"
    );
    Ok(false)
}

/// A loopback address nothing listens on right now, so tests don't collide on a fixed port.
fn free_addr() -> Result<String> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.to_string())
}

async fn spawn_server(bind: &str, _data_dir: &Path, web_dir: &Path) -> Result<GroupChild> {
    // Prefer the built binary: the test then owns the server process itself,
    // instead of a `cargo run` that would leave the real server orphaned when
    // the test's child is killed. Falls back to `cargo run`, which is the
    // portable form that works from any CWD.
    let mut cmd = match bin_path("bitmule-server", "BITMULE_SERVER_BIN") {
        Some(bin) => {
            let mut c = Command::new(bin);
            c.arg("--bind").arg(bind).arg("--no-stun").arg("--web-dir").arg(web_dir);
            c
        }
        None => {
            let mut c = Command::new(env!("CARGO"));
            c.args(["run", "--quiet", "-p", "bitmule-server", "--"])
                .arg("--bind").arg(bind).arg("--no-stun").arg("--web-dir").arg(web_dir);
            c
        }
    };
    cmd.stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        // Own process group, so Env::drop can take the whole tree down.
        .process_group(0);
    let child = cmd.spawn().context("spawn bitmule-server")?;
    wait_for_tcp(bind, Duration::from_secs(30)).await?;
    Ok(GroupChild(child))
}

async fn spawn_chromedriver(port: u16) -> Result<GroupChild> {
    let bin = std::env::var("BITMULE_CHROMEDRIVER").unwrap_or_else(|_| "chromedriver".into());
    let mut cmd = Command::new(&bin);
    cmd.arg(format!("--port={port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        // chromedriver forks Chrome; a group kill takes both.
        .process_group(0);
    let child = cmd.spawn()
        .with_context(|| format!("spawn {bin} — install chromedriver or set BITMULE_CHROMEDRIVER"))?;
    let addr = format!("127.0.0.1:{port}");
    wait_for_tcp(&addr, Duration::from_secs(10)).await?;
    Ok(GroupChild(child))
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
    let scale: f64 = 1.0 + rng.r#gen::<f64>();
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
    match bin_path("bitmule", "BITMULE_CLI") {
        Some(p) => p.to_string_lossy().into_owned(),
        // caller handles the `run -p bitmule --` prefix
        None => "cargo".into(),
    }
}

/// Spawn the CLI as a subprocess with piped stdout. Caller reads stdout
/// (typically to capture the share URL that send/recv print on start-up
/// before blocking on the transfer) and then awaits the child.
pub fn spawn_cli(server_url: &str, args: &[&str]) -> Result<Cli> {
    spawn_cli_with_stderr(server_url, args, /*capture_stderr=*/false)
}

/// Same as `spawn_cli` but pipes stderr when `capture_stderr=true`
/// so a failing test can display the child's error output. When
/// `false`, stderr inherits into the test harness so cargo test's
/// `--nocapture` can show it live.
pub fn spawn_cli_with_stderr(server_url: &str, args: &[&str], capture_stderr: bool) -> Result<Cli> {
    let bin = cli_bin();
    let (program, prefix): (&str, Vec<&str>) = if bin.ends_with("cargo") || bin == "cargo" {
        ("cargo", vec!["run", "--quiet", "-p", "bitmule", "--"])
    } else {
        (bin.as_str(), vec![])
    };
    let mut cmd = Command::new(program);
    cmd.args(&prefix)
        .arg("--unsafe").arg("--server").arg(server_url)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    if capture_stderr {
        cmd.stderr(Stdio::piped());
    } else {
        cmd.stderr(Stdio::inherit());
    }
    cmd.kill_on_drop(true).process_group(0);
    let child = cmd.spawn().context("spawn bitmule cli")?;
    Ok(GroupChild(child))
}

/// Drain a child's already-piped stderr into a String. Caller must
/// have spawned with `capture_stderr=true`. Non-blocking — reads what
/// has accumulated and returns immediately when the pipe closes or
/// there's nothing more to read.
pub async fn drain_stderr(child: &mut Child) -> String {
    use tokio::io::AsyncReadExt;
    let Some(mut se) = child.stderr.take() else { return String::new() };
    let mut buf = Vec::new();
    let _ = se.read_to_end(&mut buf).await;
    String::from_utf8_lossy(&buf).into_owned()
}

/// Read lines from a child's stdout until one contains a share URL
/// (`^share:` prefix, then `<server>/#<key>` or similar). Returns
/// the URL suitable for passing to `bitmule recv`. Replaces the
/// earlier `hex`-only extraction which broke when share keys became
/// base64url. Kenna 2026-09-13.
pub async fn read_stdout_for_share(child: &mut Child, timeout: Duration) -> Result<String> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("no piped stdout"))?;
    let mut reader = BufReader::new(stdout).lines();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, reader.next_line()).await {
            Ok(Ok(Some(line))) => {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("share:") {
                    let url = rest.trim().to_string();
                    if !url.is_empty() && url.contains("://") {
                        let mut lines = reader;
                        tokio::spawn(async move {
                            while let Ok(Some(_)) = lines.next_line().await {}
                        });
                        return Ok(url);
                    }
                }
            }
            Ok(Ok(None)) => bail!("CLI stdout closed before printing a share URL"),
            Ok(Err(e)) => bail!("CLI stdout read: {e}"),
            Err(_) => bail!("timed out waiting for share URL on CLI stdout"),
        }
    }
}

/// Read lines from a child's stdout until one contains a URL with a `#<hex>`
/// fragment (matches both `<server>/#<hex>` and `<server>/send#<hex>` per
/// Seb 2026-09-02: SPA modes 2 and 3). Returns the 64-char hex on the
/// first match, or times out after `timeout`.
#[allow(dead_code)]
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

/// Read the CLI's stdout until a share link (`#` + 90 url-safe characters, or 86
/// from a pre-checksum build) appears; the
/// rest of the output is drained in the background so the child never blocks on a full pipe.
pub async fn read_stdout_for_link(child: &mut Child, timeout: Duration) -> Result<String> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("no piped stdout"))?;
    let mut lines = BufReader::new(stdout).lines();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                if let Some((_, frag)) = line.split_once('#') {
                    let key: String = frag.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
                    if key.len() == 90 || key.len() == 86 {
                        tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
                        return Ok(key);
                    }
                }
            }
            Ok(Ok(None)) => bail!("CLI stdout closed before printing a share link"),
            Ok(Err(e)) => bail!("CLI stdout read: {e}"),
            Err(_) => bail!("timed out waiting for a share link on CLI stdout"),
        }
    }
}
