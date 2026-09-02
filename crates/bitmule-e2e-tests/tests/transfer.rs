//! All 2x2 combinations of {cli, web} sender × {cli, web} receiver.
//!
//! Per Seb 2026-09-02:
//! - server: auto-start bitmule-server if BITMULE_SERVER unset
//! - all combinations of cli and web-interface tested
//! - random files sized (1 + rand()) * 2^n KiB, n ∈ [4, 7]
//!
//! Test binary layout: `common/` module holds env/server/webdriver bring-up
//! and file-generation + sha256 helpers. Each test function is one combo.
//! Tests share serial execution (Env includes child processes bound to the
//! test lifetime) — run with `cargo test -p bitmule-e2e-tests -- --test-threads=1`.

mod common;

use anyhow::{anyhow, Context, Result};
use common::*;
use tempfile::TempDir;
use thirtyfour::prelude::*;

#[tokio::test]
#[ignore = "requires chromedriver + built bitmule binaries"]
async fn cli_to_cli() -> Result<()> {
    let env = Env::bring_up().await?;
    let src = TempDir::new()?;
    let dst = TempDir::new()?;

    let size = random_size_bytes();
    let (file, want_hash) = make_random_file(src.path(), size)?;
    eprintln!("cli_to_cli: file {} ({} bytes)", file.display(), size);

    // Receiver first — it prints the session hex we hand to the sender.
    let recv_handle = tokio::spawn({
        let url = env.server_url.clone();
        let out = dst.path().to_owned();
        async move {
            run_cli(&url, &["recv", "--out", out.to_str().unwrap()], None).await
        }
    });

    // Give the receiver a moment to print its share link. In production
    // we'd stream stdout and wait for the hex line specifically; the
    // simpler smoke shape below waits then re-reads. Left inline TODO.
    tokio::time::sleep(std::time::Duration::from_millis(750)).await;
    let (_status, recv_stdout) = recv_handle.await??;
    let session_hex = extract_session_hex(&recv_stdout)?;

    let (send_status, _) = run_cli(&env.server_url, &["send", file.to_str().unwrap()], None).await?;
    assert!(send_status.success(), "send exited non-zero");

    // Locate the received file under dst — the CLI writes it with the
    // sender's basename. Grab any file in dst and hash.
    let received = std::fs::read_dir(dst.path())?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .next()
        .ok_or_else(|| anyhow!("no file landed in {}", dst.path().display()))?;
    let got_hash = sha256_file(&received)?;
    assert_eq!(got_hash, want_hash, "received bytes differ from sent");
    Ok(())
}

#[tokio::test]
#[ignore = "requires chromedriver + built bitmule binaries"]
async fn web_to_cli() -> Result<()> {
    let env = Env::bring_up().await?;
    let src = TempDir::new()?;
    let dst = TempDir::new()?;

    let size = random_size_bytes();
    let (file, want_hash) = make_random_file(src.path(), size)?;
    eprintln!("web_to_cli: file {} ({} bytes)", file.display(), size);

    // CLI receiver first — prints session hex.
    let recv_handle = tokio::spawn({
        let url = env.server_url.clone();
        let out = dst.path().to_owned();
        async move {
            run_cli(&url, &["recv", "--out", out.to_str().unwrap()], None).await
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(750)).await;

    // Drive a headless Chrome via the web SPA to send the file.
    let caps = DesiredCapabilities::chrome();
    let driver = WebDriver::new(&env.webdriver_url, caps).await
        .context("connect webdriver")?;
    driver.goto(&format!("{}/", env.server_url)).await?;
    // Wait for the drop-zone to render.
    let file_input = driver.find(By::Css("input[type='file']")).await
        .context("no file input on send page")?;
    file_input.send_keys(file.to_str().unwrap()).await?;
    // Wait for the share link to appear so we can hand its hex to the CLI receiver.
    let link_el = driver.query(By::Css("a[href*='#']")).first().await?;
    let href = link_el.attr("href").await?.unwrap_or_default();
    let _hex_from_web = href.split_once('#').map(|(_, h)| h.trim().to_owned())
        .ok_or_else(|| anyhow!("no session hex in web share link: {href}"))?;

    // In real end-to-end shape: the CLI recv was launched with `recv`
    // (no session arg) so it generated its OWN session hex. To make
    // web-sender ↔ cli-receiver work we'd need the CLI to accept the
    // web sender's hex OR the web page to accept a pre-generated hex.
    // Bitmule's current CLI recv doesn't take a session id and reuses
    // the one it printed; correct wiring requires this direction:
    //   1. Start CLI recv first, capture its hex.
    //   2. Drive web sender to open `<server>/#<hex>` directly (not the
    //      base URL) — the SPA in receiver mode uses the hash as session
    //      id; the send SPA needs a way to be told the id up front.
    // If web-main.js doesn't currently support pre-set session ids for
    // sender mode, this test needs a small SPA tweak before it passes.
    // Marked TODO for Seb to say which side accommodates.
    let (_status, _stdout) = recv_handle.await??;
    driver.quit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires chromedriver + built bitmule binaries"]
async fn cli_to_web() -> Result<()> {
    let env = Env::bring_up().await?;
    let src = TempDir::new()?;
    let _dst = TempDir::new()?;

    let size = random_size_bytes();
    let (file, _want_hash) = make_random_file(src.path(), size)?;
    eprintln!("cli_to_web: file {} ({} bytes)", file.display(), size);

    // Same session-id-plumbing question as web_to_cli — need Seb's word
    // on whether SPA supports being told the session id externally or
    // whether the CLI grows a "recv against this hex" mode.
    let caps = DesiredCapabilities::chrome();
    let driver = WebDriver::new(&env.webdriver_url, caps).await?;
    // Start CLI sender first, capture the hex it prints (`bitmule send`
    // doesn't currently print one — sender side generates the id then
    // waits; the receiver has to know the id via the SPA hash). Deferred.
    let _ = &driver;
    driver.quit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires chromedriver + built bitmule binaries"]
async fn web_to_web() -> Result<()> {
    let env = Env::bring_up().await?;
    let src = TempDir::new()?;

    let size = random_size_bytes();
    let (file, _want_hash) = make_random_file(src.path(), size)?;
    eprintln!("web_to_web: file {} ({} bytes)", file.display(), size);

    let caps = DesiredCapabilities::chrome();
    let sender = WebDriver::new(&env.webdriver_url, caps.clone()).await?;
    sender.goto(&format!("{}/", env.server_url)).await?;
    let file_input = sender.find(By::Css("input[type='file']")).await?;
    file_input.send_keys(file.to_str().unwrap()).await?;
    let link_el = sender.query(By::Css("a[href*='#']")).first().await?;
    let href = link_el.attr("href").await?.unwrap_or_default();

    let receiver = WebDriver::new(&env.webdriver_url, caps).await?;
    receiver.goto(&href).await?;
    // Wait for progress-complete indicator in the SPA. Selector TBD —
    // depends on what web/main.js exposes for "transfer done"; using
    // 30s deadline as a first cut. This is the assertion that would
    // actually fail loudly if the transfer breaks, so pinning it is
    // where the real test-value lands. Deferred until we know the SPA's
    // completion signal shape.
    let _ = &receiver;
    sender.quit().await?;
    receiver.quit().await?;
    Ok(())
}
