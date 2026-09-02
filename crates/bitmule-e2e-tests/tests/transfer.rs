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

use anyhow::{anyhow, bail, Context, Result};
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

    // Sender-initiated (SPA mode 2 shape): `bitmule send` generates the
    // session id + prints `<server>/#<hex>` to stdout, then blocks
    // waiting for a receiver.
    let mut sender = spawn_cli(&env.server_url, &["send", file.to_str().unwrap()]).context("spawn CLI 1")?;
    let hex = read_stdout_for_hex(&mut sender, std::time::Duration::from_secs(5)).await?;

    // Receiver joins the session with the hex the sender printed.
    let mut receiver = spawn_cli(&env.server_url, &["recv", &hex, "--out", dst.path().to_str().unwrap()]).context("spawn CLI 2")?;

    // Both should exit cleanly once the DC has drained.
    let send_status = sender.wait().await?;
    let recv_status = receiver.wait().await?;
    assert!(send_status.success(), "send exited non-zero: {send_status}");
    assert!(recv_status.success(), "recv exited non-zero: {recv_status}");

    // Locate the received file under dst — the CLI writes it under the
    // sender's basename.
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

    // Web sender: open SPA at `/`, drop the file, wait for the share
    // link that carries the session hex (SPA mode 1 → mode 2 URL shape).
    let caps = DesiredCapabilities::chrome();
    let driver = WebDriver::new(&env.webdriver_url, caps).await
        .context("connect webdriver")?;
    driver.goto(&format!("{}/", env.server_url)).await?;
    let file_input = driver.find(By::Css("input[type='file']")).await
        .context("no file input on send page")?;
    file_input.send_keys(file.to_str().unwrap()).await?;
    let link_el = driver.query(By::Css("a[href*='#']")).first().await?;
    let href = link_el.attr("href").await?.unwrap_or_default();
    let hex = href.split_once('#').map(|(_, h)| h.trim().chars().take(64).collect::<String>())
        .ok_or_else(|| anyhow!("no session hex in web share link: {href}"))?;
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("share link hex bogus: {hex}");
    }

    // CLI receiver joins with the hex the web sender exposed.
    let mut receiver = spawn_cli(&env.server_url, &["recv", &hex, "--out", dst.path().to_str().unwrap()])?;
    let recv_status = receiver.wait().await?;
    assert!(recv_status.success(), "recv exited non-zero: {recv_status}");

    let received = std::fs::read_dir(dst.path())?
        .filter_map(|e| e.ok()).map(|e| e.path()).next()
        .ok_or_else(|| anyhow!("no file landed in {}", dst.path().display()))?;
    assert_eq!(sha256_file(&received)?, want_hash, "received bytes differ from sent");
    driver.quit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires chromedriver + built bitmule binaries + downloads sink"]
async fn cli_to_web() -> Result<()> {
    let env = Env::bring_up().await?;
    let src = TempDir::new()?;
    let dl = TempDir::new()?;

    let size = random_size_bytes();
    let (file, want_hash) = make_random_file(src.path(), size)?;
    eprintln!("cli_to_web: file {} ({} bytes)", file.display(), size);

    // CLI sender generates the session + prints `<server>/#<hex>`.
    let mut sender = spawn_cli(&env.server_url, &["send", file.to_str().unwrap()])?;
    let hex = read_stdout_for_hex(&mut sender, std::time::Duration::from_secs(5)).await?;

    // Point Chrome downloads at `dl` so we can hash the received file.
    let mut caps = DesiredCapabilities::chrome();
    caps.set_headless()?;
    // Chrome download-directory prefs. thirtyfour surfaces this via
    // add_experimental_option — path shape per Chromium docs.
    caps.insert_browser_option("prefs", serde_json::json!({
        "download.default_directory": dl.path().to_str().unwrap(),
        "download.prompt_for_download": false,
    }))?;

    let driver = WebDriver::new(&env.webdriver_url, caps).await?;
    let url = format!("{}/#{}", env.server_url, hex);
    driver.goto(&url).await?;

    // SPA signals completion by setting `body[data-transfer-status="complete"]`
    // at every send/recv terminal site (added to web/main.js 2026-09-02).
    driver_wait_transfer_complete(&driver, std::time::Duration::from_secs(60)).await?;
    let final_path = wait_for_final_download(dl.path(), std::time::Duration::from_secs(5)).await?;
    assert_eq!(sha256_file(&final_path)?, want_hash);

    sender.wait().await?;
    driver.quit().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires chromedriver + built bitmule binaries + downloads sink"]
async fn web_to_web() -> Result<()> {
    let env = Env::bring_up().await?;
    let src = TempDir::new()?;
    let dl = TempDir::new()?;

    let size = random_size_bytes();
    let (file, want_hash) = make_random_file(src.path(), size)?;
    eprintln!("web_to_web: file {} ({} bytes)", file.display(), size);

    // Sender browser.
    let mut send_caps = DesiredCapabilities::chrome();
    send_caps.set_headless()?;
    let sender = WebDriver::new(&env.webdriver_url, send_caps).await?;
    sender.goto(&format!("{}/", env.server_url)).await?;
    let file_input = sender.find(By::Css("input[type='file']")).await?;
    file_input.send_keys(file.to_str().unwrap()).await?;
    let link_el = sender.query(By::Css("a[href*='#']")).first().await?;
    let href = link_el.attr("href").await?.unwrap_or_default();

    // Receiver browser with downloads sink.
    let mut recv_caps = DesiredCapabilities::chrome();
    recv_caps.set_headless()?;
    recv_caps.insert_browser_option("prefs", serde_json::json!({
        "download.default_directory": dl.path().to_str().unwrap(),
        "download.prompt_for_download": false,
    }))?;
    let receiver = WebDriver::new(&env.webdriver_url, recv_caps).await?;
    receiver.goto(&href).await?;

    // SPA signals completion by setting `body[data-transfer-status="complete"]`
    // at every send/recv terminal site (added to web/main.js 2026-09-02).
    driver_wait_transfer_complete(&receiver, std::time::Duration::from_secs(60)).await?;
    let final_path = wait_for_final_download(dl.path(), std::time::Duration::from_secs(5)).await?;
    assert_eq!(sha256_file(&final_path)?, want_hash);

    sender.quit().await?;
    receiver.quit().await?;
    Ok(())
}

/// Poll the WebDriver's page for `body[data-transfer-status="complete"]`,
/// which the SPA sets at every send/recv terminal site.
async fn driver_wait_transfer_complete(driver: &WebDriver, timeout: std::time::Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let done: String = driver
            .execute("return document.body.dataset.transferStatus || '';", vec![])
            .await
            .map(|r| r.convert::<String>().unwrap_or_default())
            .unwrap_or_default();
        if done == "complete" { return Ok(()); }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    Err(anyhow!("body[data-transfer-status='complete'] never fired within {:?}", timeout))
}

/// Poll `dir` for the first file whose name doesn't end in `.crdownload`
/// (Chrome's mid-transit suffix). Returns the final PathBuf when the
/// download completes.
async fn wait_for_final_download(dir: &std::path::Path, timeout: std::time::Duration) -> Result<std::path::PathBuf> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Ok(mut it) = std::fs::read_dir(dir) {
            if let Some(entry) = it.find_map(|e| e.ok()) {
                let p = entry.path();
                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if !name.ends_with(".crdownload") && !name.is_empty() {
                    // Give one more tick for the rename to settle.
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    return Ok(p);
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    Err(anyhow!("no completed download in {} after {:?}", dir.display(), timeout))
}
