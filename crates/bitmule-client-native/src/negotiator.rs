//! WebRTC SDP+ICE negotiator, extracted from `recv_connect` per Seb
//! 2026-09-28.
//!
//! Owns the `Rtc`. Consumes `Command`s from a driver task, emits `Event`s
//! back. Networking (WS + UDP pool) lives OUTSIDE — the negotiator is
//! pure state-machine plus str0m mutations. Caller owns both transports
//! and shuttles bytes to/from the negotiator via the two mpsc channels.
//!
//! Scope: SDP offer/answer, remote ICE candidate ingest, str0m drain,
//! ChannelOpen detection. Kept OUT of scope: KEX-over-WS (KexPub /
//! KeyWrap), MetaFrame parsing, file transfer, wire_version handshake.
//! Those remain in recv_connect where they were.
//!
//! ## drain-after-mutation invariant
//!
//! str0m requires `poll_output` to be drained fully (until it returns
//! `Output::Timeout`) after every mutation — accept_offer,
//! add_remote_candidate, handle_input. `drain_and_emit` enforces that
//! and is called on every command that mutates the Rtc.
//!
//! ## lifecycle
//!
//! `run()` returns the `Rtc` back to the driver via its `Result`. The
//! driver Shutdowns the negotiator once ChannelOpen has fired and the
//! bulk-key handshake (still driven in recv_connect) is complete. The
//! Rtc then hands off to the file-transfer phase — post-open trickle
//! ICE is handled by `recv_file_over_dc` via the same helpers, without
//! going back through the negotiator.

use std::net::SocketAddr;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use str0m::{
    change::SdpOffer,
    channel::ChannelId,
    net::{Protocol, Receive},
    Candidate, Event, IceConnectionState, Input, Output, Rtc,
};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::str0m_client::PoolRecv;
use crate::SignalFrame;

/// Driver → negotiator command channel.
pub(crate) enum Command {
    /// Remote SDP frame arrived over the signaling WS. For the receiver
    /// path this is always `kind = "offer"`; the negotiator will emit a
    /// matching `WsFrame(SignalFrame::Sdp { kind: "answer", .. })` back.
    RemoteSdp { kind: String, sdp: String },
    /// A remote ICE candidate that has already been resolved (mDNS
    /// resolution is the caller's job — see `dispatch_cand_outcome` +
    /// `resolved_cand_only` in `str0m_client`).
    RemoteCandidate(Candidate),
    /// A UDP packet from the SocketPool, tagged with the specific bound
    /// local address it was delivered to (str0m's ICE agent needs this
    /// to match the packet against a known local candidate).
    Packet(PoolRecv),
    /// Driver-supplied timer tick. Fired when the driver's
    /// `sleep_until(next_timeout)` completes. Feeds `Input::Timeout`
    /// into str0m, which drives ICE keepalives / DTLS retransmits.
    Tick(Instant),
    /// Return the Rtc to the caller. Sent by the driver once
    /// `ChannelOpen` has fired and any post-open handshake it owns is
    /// done. The negotiator drains once more, then returns the Rtc.
    Shutdown,
}

/// Negotiator → driver event channel.
pub(crate) enum Event2 {
    /// A signaling frame the driver must forward over its websocket.
    WsFrame(SignalFrame),
    /// A UDP packet the driver must dispatch to its SocketPool via
    /// `send_from`. `source` = the local candidate str0m selected,
    /// `dest` = the remote endpoint.
    Transmit {
        source: SocketAddr,
        dest: SocketAddr,
        bytes: Vec<u8>,
    },
    /// str0m opened the data channel. Carries the id the negotiator
    /// side was assigned. Emitted at most once per session.
    ChannelOpen(ChannelId),
    /// The next str0m timeout. Driver should `tokio::time::sleep_until`
    /// (or equivalent) until this instant, then send `Command::Tick`.
    /// Emitted after every drain — the driver treats the latest one as
    /// authoritative and drops any earlier scheduled tick.
    NextTimeout(Instant),
}

/// Spawn a negotiator task. `rtc` should already have its local host
/// candidates loaded (see `build_rtc_with_pool_candidates` in
/// `str0m_client`). Returns the two channel endpoints plus the join
/// handle whose result is the Rtc for post-open use.
pub(crate) fn spawn(
    rtc: Rtc,
) -> (
    mpsc::UnboundedSender<Command>,
    mpsc::UnboundedReceiver<Event2>,
    tokio::task::JoinHandle<Result<Rtc>>,
) {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<Command>();
    let (ev_tx, ev_rx) = mpsc::unbounded_channel::<Event2>();
    let handle = tokio::spawn(run(rtc, cmd_rx, ev_tx));
    (cmd_tx, ev_rx, handle)
}

async fn run(
    mut rtc: Rtc,
    mut cmd_rx: mpsc::UnboundedReceiver<Command>,
    ev_tx: mpsc::UnboundedSender<Event2>,
) -> Result<Rtc> {
    // Initial drain: str0m may already have Transmits queued from the
    // local candidates + built-in DTLS bootstrap. Emit whatever's there
    // and publish the first NextTimeout.
    drain_and_emit(&mut rtc, &ev_tx)?;

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            Command::RemoteSdp { kind, sdp } => {
                if kind != "offer" {
                    // Receiver path only expects offers. Send-side
                    // (answer-handling) is a follow-up refactor.
                    warn!("negotiator: dropping unexpected SDP kind {:?}", kind);
                    continue;
                }
                let offer = SdpOffer::from_sdp_string(&sdp)
                    .map_err(|e| anyhow!("parse offer: {e}"))?;
                let answer = rtc
                    .sdp_api()
                    .accept_offer(offer)
                    .map_err(|e| anyhow!("accept_offer: {e}"))?;
                emit(&ev_tx, Event2::WsFrame(SignalFrame::Sdp {
                    kind: "answer".into(),
                    sdp: answer.to_sdp_string(),
                }))?;
                drain_and_emit(&mut rtc, &ev_tx)?;
            }
            Command::RemoteCandidate(c) => {
                rtc.add_remote_candidate(c);
                drain_and_emit(&mut rtc, &ev_tx)?;
            }
            Command::Packet(pr) => {
                let input = Input::Receive(
                    Instant::now(),
                    Receive {
                        proto: Protocol::Udp,
                        source: pr.source,
                        destination: pr.destination,
                        contents: pr
                            .bytes
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow!("packet oversize"))?,
                    },
                );
                rtc.handle_input(input)
                    .map_err(|e| anyhow!("handle_input recv: {e}"))?;
                drain_and_emit(&mut rtc, &ev_tx)?;
            }
            Command::Tick(now) => {
                rtc.handle_input(Input::Timeout(now))
                    .map_err(|e| anyhow!("handle_input timeout: {e}"))?;
                drain_and_emit(&mut rtc, &ev_tx)?;
            }
            Command::Shutdown => {
                // Final drain so any pending Transmit gets a chance to
                // land on the wire before hand-off.
                drain_and_emit(&mut rtc, &ev_tx)?;
                return Ok(rtc);
            }
        }
    }

    // cmd_tx dropped without an explicit Shutdown — treat as clean end.
    Ok(rtc)
}

/// Drain `poll_output` fully, emit every non-timeout output as an Event,
/// and end with a NextTimeout carrying the returned Timeout instant.
///
/// Correctness: str0m contract says the drain MUST run until
/// Output::Timeout before the next mutation. Every caller that mutates
/// the Rtc (accept_offer / add_remote_candidate / handle_input) is
/// followed by exactly one call to this function.
fn drain_and_emit(rtc: &mut Rtc, ev_tx: &mpsc::UnboundedSender<Event2>) -> Result<()> {
    loop {
        match rtc.poll_output().map_err(|e| anyhow!("poll_output: {e}"))? {
            Output::Timeout(t) => {
                emit(ev_tx, Event2::NextTimeout(t))?;
                return Ok(());
            }
            Output::Transmit(t) => {
                emit(ev_tx, Event2::Transmit {
                    source: t.source,
                    dest: t.destination,
                    bytes: t.contents.to_vec(),
                })?;
            }
            Output::Event(Event::ChannelOpen(id, _label)) => {
                emit(ev_tx, Event2::ChannelOpen(id))?;
            }
            Output::Event(e) => handle_generic_event(&e)?,
        }
    }
}

fn handle_generic_event(e: &Event) -> Result<()> {
    if let Event::IceConnectionStateChange(IceConnectionState::Disconnected) = e {
        bail!("ICE disconnected");
    }
    info!("str0m event: {:?}", e);
    Ok(())
}

fn emit(ev_tx: &mpsc::UnboundedSender<Event2>, ev: Event2) -> Result<()> {
    ev_tx.send(ev).context("negotiator event_tx dropped")
}

// ---- convenience wrapper: pool + pump + negotiator ---------------------

/// Filtered event the caller sees from `NegotiatorHandle`. Transmit and
/// NextTimeout are handled inside the pump (Transmit → `pool.send_from`,
/// NextTimeout → schedule the next `Tick`). The caller only deals with
/// signaling frames and channel-open notification.
#[allow(dead_code)]
pub(crate) enum HandleEvent {
    /// A signaling frame the caller must forward over its websocket.
    WsFrame(SignalFrame),
    /// The data channel opened. Handshake done from str0m's side; any
    /// per-caller post-open work (KEX completion, wire_version check)
    /// still runs in the caller loop.
    ChannelOpen(ChannelId),
}

/// Bundle returned by `spawn_with_pool`. Wraps the negotiator + a pump
/// task that owns the `SocketPool` and shuttles packets both ways:
///
///   pool.recv()   → Command::Packet   → negotiator
///   Event::Transmit                    → pool.send_from(...)
///   Event::NextTimeout(t)              → sleep_until(t) → Command::Tick
///
/// The caller drives ONLY:
///   caller.ws.next()             → HandleEvent::WsFrame(sdp/answer)  (via signaling)
///   cmd_tx.send(RemoteSdp/Cand)  (from ws frames it received)
///   handle_ev_rx.recv()          → WsFrame (forward to ws), ChannelOpen
///
/// Single-peer receive-path only. Multipeer M2b-4 needs direct SocketPool
/// control (subscribe, per-peer Rtcs on the same pool), so it constructs
/// via `spawn(rtc)` + `str0m_client::build_socket_pool` manually.
#[allow(dead_code)]
pub(crate) struct NegotiatorHandle {
    pub cmd_tx: mpsc::UnboundedSender<Command>,
    pub event_rx: mpsc::UnboundedReceiver<HandleEvent>,
    // The pump owns the pool + the negotiator's JoinHandle. On
    // `shutdown_and_reclaim` it returns (Rtc, SocketPool) so the caller
    // can hand them to LiveSession.
    pump: tokio::task::JoinHandle<Result<(Rtc, crate::str0m_client::SocketPool)>>,
}

#[allow(dead_code)]
impl NegotiatorHandle {
    /// Shut down cleanly and reclaim (Rtc, SocketPool) for the
    /// post-open file-transfer phase. Sends `Command::Shutdown`,
    /// drops the cmd_tx, drains any final HandleEvents, then awaits
    /// the pump. Order matters: dropping cmd_tx before the pump has
    /// forwarded Shutdown would race — the pump handles Shutdown
    /// itself.
    pub async fn shutdown_and_reclaim(
        mut self,
    ) -> Result<(Rtc, crate::str0m_client::SocketPool)> {
        let _ = self.cmd_tx.send(Command::Shutdown);
        drop(self.cmd_tx);
        // Consume anything the pump forwards while it drains the
        // negotiator's last outputs. If the caller cared, they'd have
        // read these already — this is post-open, so discard.
        while self.event_rx.recv().await.is_some() {}
        self.pump
            .await
            .map_err(|e| anyhow!("pump join: {e}"))?
    }
}

/// Set up the SocketPool, spawn the negotiator, and wire the pump.
/// This is the "one call to set up listeners + pool" the receiver
/// path wants. See `NegotiatorHandle` for the invariant on Transmit
/// and NextTimeout being handled internally.
#[allow(dead_code)]
pub(crate) async fn spawn_with_pool() -> Result<NegotiatorHandle> {
    let pool = crate::str0m_client::build_socket_pool().await?;
    let rtc = crate::str0m_client::build_rtc_with_pool_candidates(&pool);
    let (cmd_tx_internal, cmd_rx_internal) = mpsc::unbounded_channel::<Command>();
    let (ev_tx_internal, ev_rx_internal) = mpsc::unbounded_channel::<Event2>();
    let (handle_ev_tx, handle_ev_rx) = mpsc::unbounded_channel::<HandleEvent>();
    let neg_handle = tokio::spawn(run(rtc, cmd_rx_internal, ev_tx_internal));

    // cmd_tx returned to the caller. Pump also needs a sender so it
    // can push Command::Packet / Command::Tick / Command::Shutdown
    // (Shutdown is what the caller triggers via their cmd_tx — the
    // pump forwards it verbatim by dropping its own sender).
    let cmd_tx_pump = cmd_tx_internal.clone();
    let pump = tokio::spawn(pump(pool, cmd_tx_pump, ev_rx_internal, handle_ev_tx, neg_handle));

    Ok(NegotiatorHandle {
        cmd_tx: cmd_tx_internal,
        event_rx: handle_ev_rx,
        pump,
    })
}

async fn pump(
    mut pool: crate::str0m_client::SocketPool,
    cmd_tx: mpsc::UnboundedSender<Command>,
    mut ev_rx: mpsc::UnboundedReceiver<Event2>,
    handle_ev_tx: mpsc::UnboundedSender<HandleEvent>,
    neg_handle: tokio::task::JoinHandle<Result<Rtc>>,
) -> Result<(Rtc, crate::str0m_client::SocketPool)> {
    let mut next_timeout: Instant = Instant::now();
    // Pump ends when the negotiator's event channel closes (task
    // exited). We track that with `ev_open`; once false, no more
    // NextTimeout will arrive so the sleep branch is inert, and we
    // stop sending Packet/Tick.
    let mut ev_open = true;

    while ev_open {
        let dur = (next_timeout - Instant::now()).max(std::time::Duration::from_millis(1));
        tokio::select! {
            maybe_pr = pool.recv() => {
                match maybe_pr {
                    Some(pr) => {
                        if cmd_tx.send(Command::Packet(pr)).is_err() {
                            // negotiator gone — nothing to route packets to.
                            ev_open = false;
                        }
                    }
                    None => { ev_open = false; }
                }
            }
            maybe_ev = ev_rx.recv() => {
                match maybe_ev {
                    Some(Event2::Transmit { source, dest, bytes }) => {
                        tracing::info!("TX → {} ({} bytes)", dest, bytes.len());
                        if let Err(e) = pool.send_from(source, dest, &bytes).await {
                            tracing::warn!("pump send_from {} → {}: {}", source, dest, e);
                        }
                    }
                    Some(Event2::NextTimeout(t)) => { next_timeout = t; }
                    Some(Event2::WsFrame(f)) => {
                        if handle_ev_tx.send(HandleEvent::WsFrame(f)).is_err() {
                            ev_open = false;
                        }
                    }
                    Some(Event2::ChannelOpen(id)) => {
                        if handle_ev_tx.send(HandleEvent::ChannelOpen(id)).is_err() {
                            ev_open = false;
                        }
                    }
                    None => { ev_open = false; }
                }
            }
            _ = tokio::time::sleep(dur) => {
                if cmd_tx.send(Command::Tick(Instant::now())).is_err() {
                    ev_open = false;
                }
            }
        }
    }

    // Negotiator has exited (or is about to). Ensure the caller's
    // handle_ev_tx is closed so their event_rx.recv() returns None.
    drop(handle_ev_tx);
    // Reclaim Rtc from the negotiator task. This awaits its Result<Rtc>.
    let rtc = neg_handle
        .await
        .map_err(|e| anyhow!("negotiator join: {e}"))??;
    Ok((rtc, pool))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// Build an Rtc with one bogus host candidate so the negotiator has
    /// something to advertise, without opening a real UDP socket.
    fn test_rtc() -> Rtc {
        let mut rtc = Rtc::new(Instant::now());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5555);
        if let Ok(c) = Candidate::host(addr, "udp") {
            rtc.add_local_candidate(c);
        }
        rtc
    }

    /// Drain the event channel non-blockingly and return everything the
    /// negotiator has emitted so far.
    async fn drain_events(rx: &mut mpsc::UnboundedReceiver<Event2>) -> Vec<Event2> {
        let mut out = Vec::new();
        // A single poll cycle: yield once, then try_recv until empty.
        tokio::task::yield_now().await;
        while let Ok(ev) = rx.try_recv() {
            out.push(ev);
        }
        out
    }

    #[tokio::test]
    async fn spawns_and_emits_initial_timeout() {
        let (_cmd_tx, mut ev_rx, handle) = spawn(test_rtc());
        // Give the task a tick to run its initial drain.
        let evs = drain_events(&mut ev_rx).await;
        assert!(
            evs.iter().any(|e| matches!(e, Event2::NextTimeout(_))),
            "expected an initial NextTimeout, got {} events",
            evs.len()
        );
        // Dropping cmd_tx (already the case since we bound it to _cmd_tx
        // right above) would end run(); explicit for clarity:
        drop(_cmd_tx);
        // Task should return cleanly.
        let res = handle.await.expect("negotiator task panicked");
        assert!(res.is_ok(), "negotiator returned error: {:?}", res.err());
    }

    #[tokio::test]
    async fn shutdown_returns_rtc() {
        let (cmd_tx, mut ev_rx, handle) = spawn(test_rtc());
        let _ = drain_events(&mut ev_rx).await;
        cmd_tx.send(Command::Shutdown).unwrap();
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("negotiator did not shut down in time")
            .expect("negotiator task panicked");
        assert!(res.is_ok(), "shutdown returned error: {:?}", res.err());
    }

    #[tokio::test]
    async fn bogus_sdp_offer_errors_cleanly() {
        let (cmd_tx, mut ev_rx, handle) = spawn(test_rtc());
        let _ = drain_events(&mut ev_rx).await;
        cmd_tx
            .send(Command::RemoteSdp {
                kind: "offer".into(),
                sdp: "this is not valid SDP".into(),
            })
            .unwrap();
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .expect("negotiator did not terminate on bad SDP")
            .expect("negotiator task panicked");
        assert!(res.is_err(), "expected parse error, got Ok");
    }
}
