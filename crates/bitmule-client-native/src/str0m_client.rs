//! str0m-based rewrite spike per Seb 2026-09-02.
//!
//! One `Rtc` instance per connection. No spawned aux tasks. No callbacks.
//! Everything (UDP socket, WS signaling, str0m mutations + poll_output
//! drain) lives inside a single `select!` loop per entry point.
//!
//! str0m contract from the README: **every mutation must be followed by
//! a complete drain of `poll_output` until it returns Output::Timeout,
//! before the next mutation on the same Rtc.** `drain_rtc()` enforces
//! this — call it after every handle_input / sdp_api mutation / channel
//! write.
//!
//! Compile-broken in places (marked `todo!()` where str0m surface details
//! need pinning down against the crate — Candidate::from_sdp_string
//! signature, SdpOffer::from_sdp_string, MDNS candidate integration
//! into str0m's Candidate parser, etc). Structure is the point.
//!
//! Out of scope for this spike: relay-mode transport (unchanged, still
//! all-WS), file transfer over the data channel (send_file_over_dc /
//! recv_file_over_dc need rewriting against str0m::Channel — separate pass).

use std::{net::SocketAddr, sync::Arc, time::Instant};

use anyhow::{anyhow, bail, Context, Result};
use bitmule_core::SessionId;
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use str0m::{
    change::{SdpAnswer, SdpOffer, SdpPendingOffer},
    channel::{ChannelData, ChannelId},
    net::{Protocol, Receive},
    Candidate, Event, IceConnectionState, Input, Output, Rtc,
};
use tokio::net::UdpSocket;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::{Role, SignalFrame, Ws};

/// A live str0m-backed session. Owner holds the Rtc + its socket + the
/// signaling WS. Follow-on file transfer functions borrow `&mut Self`
/// and drive their own select! loop over the same fields.
pub struct LiveSessionStr0m {
    pub session_id: SessionId,
    pub role: Role,
    pub rtc: Rtc,
    pub socket: Arc<UdpSocket>,
    pub ws: Ws,
    pub channel_id: ChannelId,
}

/// Build a fresh Rtc + bind a UDP socket + register the socket's local
/// addr as a host candidate. STUN servers are configured via the
/// str0m::RtcConfig if needed — the initial spike uses defaults and
/// relies on trickle from the remote side.
async fn build_rtc() -> Result<(Rtc, Arc<UdpSocket>)> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.context("bind udp")?;
    let local = socket.local_addr().context("local_addr")?;
    let socket = Arc::new(socket);

    let mut rtc = Rtc::new();

    // str0m expects the host candidate to reflect the routable address it
    // will announce over signaling. For a NAT-behind host this is still
    // the socket's local addr on the LAN; STUN/srflx candidates come
    // trickled in by the remote side + gathered by str0m internally when
    // ICE servers are configured on the builder.
    let cand = Candidate::host(local, "udp").map_err(|e| anyhow!("host candidate: {e}"))?;
    rtc.add_local_candidate(cand);

    Ok((rtc, socket))
}

/// Sender entry point — active side: create data channel, produce offer,
/// send over WS, wait for answer, run loop until ChannelOpen.
pub async fn send_connect(server_url: &str, session_id: SessionId) -> Result<LiveSessionStr0m> {
    let session_hex = session_id.as_hex();
    info!(session = %session_hex, "opening sender WS + Rtc");

    let ws = crate::open_ws(server_url, &session_hex).await?;
    let (mut rtc, socket) = build_rtc().await?;

    // Active side: create the data channel BEFORE offer generation so its
    // m-line lands in the SDP. Channel id is stable — hold onto it.
    let mut change = rtc.sdp_api();
    let channel_id = change.add_channel("bitmule".into());
    let (offer, pending): (SdpOffer, SdpPendingOffer) = change
        .apply()
        .ok_or_else(|| anyhow!("sdp_api produced no offer — nothing added"))?;
    drain_rtc(&mut rtc, &socket, None).await?; // per str0m single-mutation invariant

    let mut ws = ws; // shadow so we can borrow &mut
    ws_send(&mut ws, &SignalFrame::Hello {
        role: Role::Sender.as_str().to_owned(),
        receiver_id: None,
    }).await?;

    // Wait for receiver peer_hello — inline in the run loop below. Offer
    // is sent as soon as peer_hello arrives so we don't spam SDP into a
    // room with no receiver.
    let mut peer_hello_seen = false;
    let mut offer_sent = false;
    let mut opt_pending: Option<SdpPendingOffer> = Some(pending);
    let mut opt_offer: Option<SdpOffer> = Some(offer);

    run_until_channel_open(
        &mut rtc,
        &socket,
        &mut ws,
        channel_id,
        Some(&mut |rtc: &mut Rtc, ws: &mut Ws, frame: SignalFrame| {
            let peer_hello_seen = &mut peer_hello_seen;
            let offer_sent = &mut offer_sent;
            let opt_pending = &mut opt_pending;
            let opt_offer = &mut opt_offer;
            Box::pin(async move {
                match frame {
                    SignalFrame::PeerHello { .. } if !*peer_hello_seen => {
                        *peer_hello_seen = true;
                        let offer = opt_offer.take().expect("offer set on entry");
                        ws_send(ws, &SignalFrame::Sdp {
                            kind: "offer".into(),
                            sdp: offer.to_sdp_string(),
                        }).await?;
                        *offer_sent = true;
                        debug!("offer sent");
                    }
                    SignalFrame::Sdp { kind, sdp } if kind == "answer" && *offer_sent => {
                        let ans = SdpAnswer::from_sdp_string(&sdp)
                            .map_err(|e| anyhow!("parse answer: {e}"))?;
                        let pending = opt_pending.take().expect("pending set on entry");
                        rtc.sdp_api().accept_answer(pending, ans)
                            .map_err(|e| anyhow!("accept_answer: {e}"))?;
                    }
                    _ => {}
                }
                Ok(())
            })
        }),
    ).await?;

    Ok(LiveSessionStr0m { session_id, role: Role::Sender, rtc, socket, ws, channel_id })
}

/// Receiver entry point — passive side: send hello + peer_hello, wait
/// for offer, produce + send answer, run loop until ChannelOpen (which
/// carries the id str0m assigned on the passive side).
pub async fn recv_connect(server_url: &str, session_id: SessionId) -> Result<LiveSessionStr0m> {
    let session_hex = session_id.as_hex();
    info!(session = %session_hex, "opening receiver WS + Rtc");

    let ws = crate::open_ws(server_url, &session_hex).await?;
    let (mut rtc, socket) = build_rtc().await?;
    let mut ws = ws;

    let receiver_id = SessionId::random().as_hex();
    ws_send(&mut ws, &SignalFrame::Hello {
        role: Role::Receiver.as_str().to_owned(),
        receiver_id: Some(receiver_id.clone()),
    }).await?;
    ws_send(&mut ws, &SignalFrame::PeerHello { receiver_id: Some(receiver_id) }).await?;

    // Passive side gets the channel_id from the Event::ChannelOpen — not
    // known up front. run_until_channel_open captures + returns it.
    let opened_id = run_until_channel_open_and_capture_id(
        &mut rtc,
        &socket,
        &mut ws,
        Some(&mut |rtc: &mut Rtc, ws: &mut Ws, frame: SignalFrame| {
            Box::pin(async move {
                if let SignalFrame::Sdp { kind, sdp } = frame {
                    if kind == "offer" {
                        let offer = SdpOffer::from_sdp_string(&sdp)
                            .map_err(|e| anyhow!("parse offer: {e}"))?;
                        let answer = rtc.sdp_api().accept_offer(offer)
                            .map_err(|e| anyhow!("accept_offer: {e}"))?;
                        ws_send(ws, &SignalFrame::Sdp {
                            kind: "answer".into(),
                            sdp: answer.to_sdp_string(),
                        }).await?;
                        debug!("answer sent");
                    }
                }
                Ok(())
            })
        }),
    ).await?;

    Ok(LiveSessionStr0m { session_id, role: Role::Receiver, rtc, socket, ws, channel_id: opened_id })
}

// ---- run-loop core ------------------------------------------------------

/// Drain str0m's poll_output queue after any mutation, forwarding
/// Transmit outputs to the socket, dispatching Events, and returning
/// the next Timeout deadline. Enforces str0m's single-mutation invariant.
///
/// `on_event` optional — used when the caller wants to react to
/// non-terminal events (ICE state changes, ChannelData). ChannelOpen is
/// caller's concern (handled in the run_until_channel_open variants).
async fn drain_rtc(
    rtc: &mut Rtc,
    socket: &UdpSocket,
    mut on_event: Option<&mut dyn FnMut(Event)>,
) -> Result<Instant> {
    loop {
        match rtc.poll_output().map_err(|e| anyhow!("poll_output: {e}"))? {
            Output::Timeout(t) => return Ok(t),
            Output::Transmit(t) => {
                socket.send_to(&t.contents, t.destination).await
                    .with_context(|| format!("send_to {}", t.destination))?;
            }
            Output::Event(e) => {
                if let Event::IceConnectionStateChange(IceConnectionState::Disconnected) = &e {
                    bail!("ICE disconnected");
                }
                if let Some(cb) = on_event.as_deref_mut() {
                    cb(e);
                }
            }
        }
    }
}

type SignalCb<'a> = dyn FnMut(&mut Rtc, &mut Ws, SignalFrame) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> + Send + 'a;

/// Sender loop: runs until Event::ChannelOpen(known_id, _).
async fn run_until_channel_open<'a>(
    rtc: &mut Rtc,
    socket: &UdpSocket,
    ws: &mut Ws,
    expected: ChannelId,
    mut on_signal: Option<&mut SignalCb<'a>>,
) -> Result<()> {
    let mut buf = vec![0u8; 2000];
    let mut opened = false;
    let mut next_timeout = drain_rtc(rtc, socket, None).await?;

    while !opened {
        let dur = (next_timeout - Instant::now()).max(std::time::Duration::from_millis(1));

        tokio::select! {
            // WS inbound (signaling from peer via server)
            maybe_msg = ws.next() => {
                let text = match maybe_msg {
                    Some(Ok(Message::Text(t))) => t.to_string(),
                    Some(Ok(Message::Close(_))) | None => bail!("ws closed pre-channel-open"),
                    Some(Err(e)) => bail!("ws recv: {e}"),
                    _ => continue,
                };
                let frame: SignalFrame = match serde_json::from_str(&text) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                // ICE trickle from peer routes into str0m directly here.
                if let SignalFrame::Ice { candidate: Some(c) } = &frame {
                    if let Some(remote) = parse_ice_candidate(c) {
                        rtc.add_remote_candidate(remote);
                        next_timeout = drain_rtc(rtc, socket, None).await?;
                    }
                }
                // Non-ICE frames (SDP offer/answer/hello) delegate to caller.
                if let Some(cb) = on_signal.as_deref_mut() {
                    cb(rtc, ws, frame).await?;
                    next_timeout = drain_rtc(rtc, socket, None).await?;
                }
            }

            // UDP inbound (media/DTLS/STUN)
            r = socket.recv_from(&mut buf) => {
                let (n, source) = r.context("udp recv_from")?;
                let local = socket.local_addr().context("local_addr")?;
                let input = Input::Receive(Instant::now(), Receive {
                    proto: Protocol::Udp,
                    source,
                    destination: local,
                    contents: (&buf[..n]).try_into().map_err(|_| anyhow!("packet oversize"))?,
                });
                rtc.handle_input(input).map_err(|e| anyhow!("handle_input recv: {e}"))?;
                next_timeout = drain_rtc(rtc, socket, Some(&mut |e| {
                    if let Event::ChannelOpen(id, _label) = e {
                        if id == expected { opened = true; }
                    }
                })).await?;
            }

            // Str0m timeout wake — advance the engine to the deadline.
            _ = tokio::time::sleep(dur) => {
                rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("handle_input timeout: {e}"))?;
                next_timeout = drain_rtc(rtc, socket, Some(&mut |e| {
                    if let Event::ChannelOpen(id, _label) = e {
                        if id == expected { opened = true; }
                    }
                })).await?;
            }
        }
    }
    info!("data channel open");
    Ok(())
}

/// Receiver variant: str0m assigns the ChannelId on the passive side, so
/// we return it instead of taking it as input.
async fn run_until_channel_open_and_capture_id<'a>(
    rtc: &mut Rtc,
    socket: &UdpSocket,
    ws: &mut Ws,
    mut on_signal: Option<&mut SignalCb<'a>>,
) -> Result<ChannelId> {
    let mut buf = vec![0u8; 2000];
    let mut opened: Option<ChannelId> = None;
    let mut next_timeout = drain_rtc(rtc, socket, None).await?;

    while opened.is_none() {
        let dur = (next_timeout - Instant::now()).max(std::time::Duration::from_millis(1));

        tokio::select! {
            maybe_msg = ws.next() => {
                let text = match maybe_msg {
                    Some(Ok(Message::Text(t))) => t.to_string(),
                    Some(Ok(Message::Close(_))) | None => bail!("ws closed pre-channel-open"),
                    Some(Err(e)) => bail!("ws recv: {e}"),
                    _ => continue,
                };
                let frame: SignalFrame = match serde_json::from_str(&text) { Ok(f) => f, Err(_) => continue };
                if let SignalFrame::Ice { candidate: Some(c) } = &frame {
                    if let Some(remote) = parse_ice_candidate(c) {
                        rtc.add_remote_candidate(remote);
                        next_timeout = drain_rtc(rtc, socket, None).await?;
                    }
                }
                if let Some(cb) = on_signal.as_deref_mut() {
                    cb(rtc, ws, frame).await?;
                    next_timeout = drain_rtc(rtc, socket, None).await?;
                }
            }

            r = socket.recv_from(&mut buf) => {
                let (n, source) = r.context("udp recv_from")?;
                let local = socket.local_addr().context("local_addr")?;
                let input = Input::Receive(Instant::now(), Receive {
                    proto: Protocol::Udp,
                    source,
                    destination: local,
                    contents: (&buf[..n]).try_into().map_err(|_| anyhow!("packet oversize"))?,
                });
                rtc.handle_input(input).map_err(|e| anyhow!("handle_input recv: {e}"))?;
                next_timeout = drain_rtc(rtc, socket, Some(&mut |e| {
                    if let Event::ChannelOpen(id, _label) = e {
                        opened = Some(id);
                    }
                })).await?;
            }

            _ = tokio::time::sleep(dur) => {
                rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("handle_input timeout: {e}"))?;
                next_timeout = drain_rtc(rtc, socket, Some(&mut |e| {
                    if let Event::ChannelOpen(id, _label) = e {
                        opened = Some(id);
                    }
                })).await?;
            }
        }
    }
    let id = opened.unwrap();
    info!("data channel open (id={:?})", id);
    Ok(id)
}

// ---- helpers ------------------------------------------------------------

async fn ws_send(ws: &mut Ws, frame: &SignalFrame) -> Result<()> {
    let text = serde_json::to_string(frame).context("frame encode")?;
    ws.send(Message::Text(text.into())).await.context("ws send")?;
    Ok(())
}

/// Parse a browser-style ICE candidate JSON blob into a str0m Candidate.
/// Browser sends `{"candidate":"candidate:...","sdpMid":"0","sdpMLineIndex":0,"usernameFragment":"..."}`.
/// str0m's Candidate::from_sdp_string wants just the "candidate:..." payload.
/// mDNS `.local` addresses need pre-resolution via [`crate::maybe_resolve_mdns_candidate`].
fn parse_ice_candidate(v: &serde_json::Value) -> Option<Candidate> {
    let line = v.get("candidate")?.as_str()?;
    if line.is_empty() { return None; }
    // TODO: mDNS resolution — call the existing async resolver, then feed here.
    // For now, drop mDNS candidates on the floor.
    if line.split_whitespace().nth(4).map_or(false, |a| a.ends_with(".local")) {
        warn!("dropping mdns ICE candidate (mdns resolver not wired into str0m path yet)");
        return None;
    }
    match Candidate::from_sdp_string(line) {
        Ok(c) => Some(c),
        Err(e) => { warn!("bad ice candidate: {e}"); None }
    }
}
