//! All combinations of {cli, web} sender × {cli, web} receiver, over the relay and over WebRTC.
//!
//! The browser is driven with thirtyfour against `web/test/page.html`, which loads the same
//! `v2.js` the real pages use; the CLI is the built `bitmule` binary. The server is started by
//! the test (on a free port) unless BITMULE_SERVER is set.
//!
//!     cargo build -p bitmule -p bitmule-server
//!     cargo test -p bitmule-e2e-tests --test transfer -- --ignored --test-threads=1

mod common;

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use common::*;
use serde_json::{Value, json};
use tempfile::TempDir;
use thirtyfour::prelude::*;

const TIMEOUT: Duration = Duration::from_secs(30);

// JS: receive a share link; resolves {sha, size, kind, relayBytes, directBytes} or {error}
const RECEIVE: &str = r#"
const [server, link] = args;
return await new Promise((resolve) => {
  v2.startReceive({ server, link, on: {
    done: async (d) => {
      const buf = new Uint8Array(await d.file.arrayBuffer());
      const sha = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", buf))).map(b => b.toString(16).padStart(2, "0")).join("");
      resolve({ sha, size: d.size, kind: d.kind, relayBytes: d.relayBytes, directBytes: d.directBytes });
    },
    error: (m) => resolve({ error: m }),
  }});
});
"#;

// JS: send the file picked in the page's file input; the link and the result appear in window.*
const SEND: &str = r#"
const [server, requestKey] = args;
const file = document.getElementById("file").files[0];
window.link = null; window.sendResult = null;
v2.startSend({ server, blob: file, kind: "single", requestKey: requestKey || null, on: {
  link: (l) => { window.link = l; },
  done: (m) => { window.sendResult = { sent: m.receivers }; },
  error: (m) => { window.sendResult = { error: m }; },
}});
return true;
"#;

// JS: ask for a file; the key appears in window.reqKey, the result in window.reqResult
const REQUEST_AND_RECEIVE: &str = r#"
const [server] = args;
window.reqKey = null; window.reqResult = null;
v2.startRequest({ server, on: {
  requestKey: (k) => { window.reqKey = k; },
  shareLink: (link) => {
    v2.startReceive({ server, link, on: {
      done: async (d) => {
        const buf = new Uint8Array(await d.file.arrayBuffer());
        const sha = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", buf))).map(b => b.toString(16).padStart(2, "0")).join("");
        window.reqResult = { sha, direct: d.directBytes, relay: d.relayBytes };
      },
      error: (m) => { window.reqResult = { error: m }; },
    }});
  },
  error: (m) => { window.reqResult = { error: m }; },
}});
return true;
"#;

struct Page {
    driver: WebDriver,
    server: String,
}

impl Page {
    async fn open(env: &Env) -> Result<Page> {
        let mut caps = DesiredCapabilities::chrome();
        for arg in ["--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                    // real host candidates, not mDNS names, so the CLI's WebRTC can reach us
                    "--disable-features=WebRtcHideLocalIpsWithMdns"] {
            caps.add_arg(arg)?;
        }
        let driver = WebDriver::new(&env.webdriver_url, caps).await.context("start chrome")?;
        driver.set_script_timeout(TIMEOUT).await?;
        driver.goto(format!("{}/test/page.html", env.server_url)).await?;
        let page = Page { driver, server: env.server_url.clone() };
        page.wait("!!window.testReady").await.context("page never became ready")?;
        Ok(page)
    }

    /// Run async JS; `args` is its `args`; returns what it returns.
    async fn run(&self, body: &str, args: Vec<Value>) -> Result<Value> {
        let script = format!(
            "const done = arguments[arguments.length - 1];\
             const args = Array.from(arguments).slice(0, -1);\
             (async () => {{{body}}})().then(done, (e) => done({{error: String(e && e.stack || e)}}));");
        let ret = self.driver.execute_async(script, args).await?;
        Ok(ret.json().clone())
    }

    /// Wait until the JS expression is truthy; returns its value.
    async fn wait(&self, expr: &str) -> Result<Value> {
        let end = Instant::now() + TIMEOUT;
        while Instant::now() < end {
            let v = self.driver.execute(format!("return {expr};"), vec![]).await?.json().clone();
            if !matches!(v, Value::Null | Value::Bool(false)) {
                return Ok(v);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        bail!("timeout waiting for `{expr}`")
    }

    async fn pick_file(&self, path: &std::path::Path) -> Result<()> {
        self.driver.find(By::Id("file")).await?.send_keys(path.to_str().unwrap()).await?;
        Ok(())
    }

    async fn close(self) {
        let _ = self.driver.quit().await;
    }
}

fn hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

fn check_received(result: &Value, want: &[u8; 32], transport: &str) -> Result<()> {
    if let Some(e) = result.get("error") {
        bail!("receive failed: {e}");
    }
    assert_eq!(result["sha"], json!(hex(want)), "received data differs");
    if transport == "--webrtc" {
        let direct = result.get("directBytes").or(result.get("direct")).and_then(Value::as_u64).unwrap_or(0);
        assert!(direct > 0, "nothing came over the data channel: {result}");
    }
    Ok(())
}

fn only_file(dir: &std::path::Path) -> Result<std::path::PathBuf> {
    let files: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    match files.as_slice() {
        [one] => Ok(one.clone()),
        other => Err(anyhow!("expected one received file, got {other:?}")),
    }
}

async fn cli_to_cli(transport: &str) -> Result<()> {
    let env = Env::bring_up_server_only().await?;
    let (src, dst) = (TempDir::new()?, TempDir::new()?);
    let (file, want) = make_random_file(src.path(), random_size_bytes())?;

    let mut sender = spawn_cli(&env.server_url, &["send", transport, file.to_str().unwrap()])?;
    let key = read_stdout_for_link(&mut sender, TIMEOUT).await?;
    let link = format!("{}/#{key}", env.server_url);
    let mut receiver = spawn_cli(&env.server_url, &["recv", transport, "--out", dst.path().to_str().unwrap(), &link])?;

    let (s, r) = tokio::time::timeout(TIMEOUT, async { (sender.wait().await, receiver.wait().await) }).await?;
    assert!(s?.success(), "send failed");
    assert!(r?.success(), "recv failed");
    assert_eq!(sha256_file(&only_file(dst.path())?)?, want);
    Ok(())
}

async fn web_to_cli(transport: &str) -> Result<()> {
    let env = Env::bring_up().await?;
    let (src, dst) = (TempDir::new()?, TempDir::new()?);
    let (file, want) = make_random_file(src.path(), random_size_bytes())?;

    let page = Page::open(&env).await?;
    page.pick_file(&file).await?;
    page.run(SEND, vec![json!(page.server), Value::Null]).await?;
    let key = page.wait("window.link").await?;
    let link = format!("{}/#{}", env.server_url, key.as_str().unwrap());
    let mut receiver = spawn_cli(&env.server_url, &["recv", transport, "--out", dst.path().to_str().unwrap(), &link])?;
    let status = tokio::time::timeout(TIMEOUT, receiver.wait()).await??;
    assert!(status.success(), "recv failed");
    assert_eq!(sha256_file(&only_file(dst.path())?)?, want);
    let sent = page.wait("window.sendResult").await?;
    assert!(sent.get("error").is_none(), "web sender: {sent}");
    page.close().await;
    Ok(())
}

async fn cli_to_web(transport: &str) -> Result<()> {
    let env = Env::bring_up().await?;
    let src = TempDir::new()?;
    let (file, want) = make_random_file(src.path(), random_size_bytes())?;

    let mut sender = spawn_cli(&env.server_url, &["send", transport, file.to_str().unwrap()])?;
    let key = read_stdout_for_link(&mut sender, TIMEOUT).await?;
    let page = Page::open(&env).await?;
    let result = page.run(RECEIVE, vec![json!(page.server), json!(key)]).await?;
    check_received(&result, &want, transport)?;
    let status = tokio::time::timeout(TIMEOUT, sender.wait()).await??;
    assert!(status.success(), "send failed");
    page.close().await;
    Ok(())
}

/// Browsers cannot force a transport (auto mode: a small file may finish over the relay first).
async fn web_pair(_: ()) -> Result<()> {
    let env = Env::bring_up().await?;
    let src = TempDir::new()?;
    let (file, want) = make_random_file(src.path(), random_size_bytes())?;

    let (sender, receiver) = (Page::open(&env).await?, Page::open(&env).await?);
    sender.pick_file(&file).await?;
    sender.run(SEND, vec![json!(sender.server), Value::Null]).await?;
    let key = sender.wait("window.link").await?;
    let result = receiver.run(RECEIVE, vec![json!(receiver.server), key]).await?;
    check_received(&result, &want, "auto")?;
    let sent = sender.wait("window.sendResult").await?;
    assert!(sent.get("error").is_none(), "web sender: {sent}");
    sender.close().await;
    receiver.close().await;
    Ok(())
}

/// The receiver asks first (the request key), the sender answers it.
async fn web_to_web_request() -> Result<()> {
    let env = Env::bring_up().await?;
    let src = TempDir::new()?;
    let (file, want) = make_random_file(src.path(), random_size_bytes())?;

    let (receiver, sender) = (Page::open(&env).await?, Page::open(&env).await?);
    receiver.run(REQUEST_AND_RECEIVE, vec![json!(receiver.server)]).await?;
    let key = receiver.wait("window.reqKey").await?;
    sender.pick_file(&file).await?;
    sender.run(SEND, vec![json!(sender.server), key]).await?;
    let result = receiver.wait("window.reqResult").await?;
    check_received(&result, &want, "--relay")?;
    let sent = sender.wait("window.sendResult").await?;
    assert!(sent.get("error").is_none(), "web sender: {sent}");
    sender.close().await;
    receiver.close().await;
    Ok(())
}

macro_rules! combos {
    ($($name:ident => $f:ident($t:expr);)*) => {$(
        #[tokio::test]
        #[ignore = "needs chromedriver + built bitmule and bitmule-server"]
        async fn $name() -> Result<()> { $f($t).await }
    )*};
}

combos! {
    cli_to_cli_relay => cli_to_cli("--relay");
    cli_to_cli_webrtc => cli_to_cli("--webrtc");
    web_to_cli_relay => web_to_cli("--relay");
    web_to_cli_webrtc => web_to_cli("--webrtc");
    cli_to_web_relay => cli_to_web("--relay");
    cli_to_web_webrtc => cli_to_web("--webrtc");
    web_to_web => web_pair(());
}

#[tokio::test]
#[ignore = "needs chromedriver + built bitmule and bitmule-server"]
async fn web_to_web_requested() -> Result<()> { web_to_web_request().await }
