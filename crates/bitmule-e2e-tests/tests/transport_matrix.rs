//! Transport-matrix test: every CLI sender-mode × CLI receiver-mode
//! combination, in parallel, 10s timeout per case.
//!
//! Seb 2026-09-13: modify bitmule-e2e-tests to do the matrix rather
//! than a bash script — proper cargo test with per-case isolation +
//! parallel execution + timeout.
//!
//! Modes tested per side: auto (no flag), --relay, --webrtc.
//! That's 3 × 3 = 9 combinations. Each case:
//!   - Fresh temp dir for output.
//!   - Sender spawned, prints share URL on stdout.
//!   - Receiver spawned with the URL.
//!   - Wait for both to exit OR 10s deadline.
//!   - Verify sha256 of received file matches sent.
//!
//! Cases share the same server (single Env::bring_up_server_only()
//! call) so setup cost is amortized. Server is dropped after all
//! cases return.
//!
//! Ignored by default because it needs the bitmule + bitmule-server
//! binaries built and running WebRTC may require reachable STUN/TURN
//! for the --webrtc cases to complete. To run:
//!   cargo test -p bitmule-e2e-tests --test transport_matrix -- --ignored --nocapture

mod common;

use anyhow::{anyhow, Context, Result};
use common::*;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;

const PER_CASE_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires built bitmule binaries; --webrtc cases need reachable STUN"]
async fn transport_matrix() -> Result<()> {
    let env = Arc::new(Env::bring_up_server_only().await?);

    // (label, sender_mode_flag, recv_mode_flag). Empty string = auto (no flag).
    let cases: &[(&str, &str, &str)] = &[
        ("auto_send   -> auto_recv",   "",         ""),
        ("auto_send   -> relay_recv",  "",         "--relay"),
        ("auto_send   -> webrtc_recv", "",         "--webrtc"),
        ("relay_send  -> auto_recv",   "--relay",  ""),
        ("relay_send  -> relay_recv",  "--relay",  "--relay"),
        ("relay_send  -> webrtc_recv", "--relay",  "--webrtc"),
        ("webrtc_send -> auto_recv",   "--webrtc", ""),
        ("webrtc_send -> relay_recv",  "--webrtc", "--relay"),
        ("webrtc_send -> webrtc_recv", "--webrtc", "--webrtc"),
    ];

    let mut handles = Vec::with_capacity(cases.len());
    for (label, sflag, rflag) in cases {
        let env = Arc::clone(&env);
        let label = label.to_string();
        let sflag = sflag.to_string();
        let rflag = rflag.to_string();
        handles.push(tokio::spawn(async move {
            let outcome = timeout(PER_CASE_TIMEOUT, run_one_case(&env, &sflag, &rflag)).await;
            let msg = match outcome {
                Err(_) => format!("TIMEOUT (>{}s)", PER_CASE_TIMEOUT.as_secs()),
                Ok(Err(e)) => format!("FAIL: {e:#}"),
                Ok(Ok(())) => "PASS".to_string(),
            };
            (label, msg)
        }));
    }

    let mut passed = 0;
    let mut failed = 0;
    let mut lines = Vec::new();
    for h in handles {
        let (label, msg) = h.await.expect("task panic");
        if msg == "PASS" {
            passed += 1;
        } else {
            failed += 1;
        }
        lines.push(format!("  {:32} {}", label, msg));
    }
    lines.sort();
    eprintln!("\n=== transport matrix ({} passed, {} failed) ===", passed, failed);
    for l in &lines {
        eprintln!("{l}");
    }
    if failed > 0 {
        Err(anyhow!("{failed}/{} cases failed — see per-case output above", cases.len()))
    } else {
        Ok(())
    }
}

/// One (sender_mode, receiver_mode) pair. Spawn sender, capture its
/// share URL, spawn receiver with that URL, wait for both to exit,
/// verify sha256 of the received file matches sent.
async fn run_one_case(env: &Env, sender_flag: &str, recv_flag: &str) -> Result<()> {
    let src = TempDir::new()?;
    let dst = TempDir::new()?;
    let (file, want_hash) = make_random_file(src.path(), random_size_bytes())?;

    let mut send_args: Vec<&str> = Vec::new();
    send_args.push("send");
    if !sender_flag.is_empty() { send_args.push(sender_flag); }
    send_args.push(file.to_str().unwrap());

    let mut sender = spawn_cli(&env.server_url, &send_args).context("spawn sender")?;
    let share_url = read_stdout_for_share(&mut sender, Duration::from_secs(4))
        .await
        .context("read sender share URL")?;

    let mut recv_args: Vec<&str> = Vec::new();
    recv_args.push("recv");
    if !recv_flag.is_empty() { recv_args.push(recv_flag); }
    recv_args.push(&share_url);
    recv_args.push("--out");
    recv_args.push(dst.path().to_str().unwrap());

    let mut receiver = spawn_cli(&env.server_url, &recv_args).context("spawn receiver")?;

    let (send_res, recv_res) = tokio::join!(sender.wait(), receiver.wait());
    let send_status = send_res.context("sender wait")?;
    let recv_status = recv_res.context("receiver wait")?;
    if !send_status.success() {
        return Err(anyhow!("sender exit {send_status}"));
    }
    if !recv_status.success() {
        return Err(anyhow!("receiver exit {recv_status}"));
    }

    let received = std::fs::read_dir(dst.path())?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .next()
        .ok_or_else(|| anyhow!("no file landed in {}", dst.path().display()))?;
    let got_hash = sha256_file(&received)?;
    if got_hash != want_hash {
        return Err(anyhow!("received hash mismatch"));
    }
    Ok(())
}
