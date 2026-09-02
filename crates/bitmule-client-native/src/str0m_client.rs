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
//! Out of scope for this spike: relay-mode transport (unchanged, still
//! all-WS), file transfer over the data channel (send_file_over_dc /
//! recv_file_over_dc need rewriting against str0m::Channel — separate pass).

use std::{path::{Path, PathBuf}, sync::Arc, time::Instant};

use anyhow::{anyhow, bail, Context, Result};
use bitmule_core::SessionId;
use futures_util::{SinkExt, StreamExt};
use str0m::{
    change::{SdpAnswer, SdpOffer},
    channel::{ChannelData, ChannelId},
    net::{Protocol, Receive},
    Candidate, Event, IceConnectionState, Input, Output, Rtc,
};
use tokio::{io::AsyncWriteExt, net::UdpSocket};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::{MetaFrame, Role, SignalFrame, Ws};

/// A live str0m-backed session. Owner holds the Rtc + its socket + the
/// signaling WS. Follow-on file transfer functions borrow `&mut Self`
/// and drive their own select! loop over the same fields.
pub struct LiveSession {
    pub session_id: SessionId,
    pub role: Role,
    pub rtc: Rtc,
    pub socket: Arc<UdpSocket>,
    pub ws: Ws,
    pub channel_id: ChannelId,
}

/// Build a fresh Rtc + bind a UDP socket + register the socket's local
/// addr as a host candidate.
async fn build_rtc() -> Result<(Rtc, Arc<UdpSocket>)> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.context("bind udp")?;
    let local = socket.local_addr().context("local_addr")?;
    let socket = Arc::new(socket);

    let mut rtc = Rtc::new(Instant::now());
    let cand = Candidate::host(local, "udp").map_err(|e| anyhow!("host candidate: {e}"))?;
    rtc.add_local_candidate(cand);

    Ok((rtc, socket))
}

/// Sender entry point — active side: create data channel, produce offer,
/// send over WS, wait for answer, run loop until ChannelOpen.
pub async fn send_connect(server_url: &str, session_id: SessionId) -> Result<LiveSession> {
    let session_hex = session_id.as_hex();
    info!(session = %session_hex, "opening sender WS + Rtc");

    let mut ws = crate::open_ws(server_url, &session_hex).await?;
    let (mut rtc, socket) = build_rtc().await?;

    // Active side: create the data channel BEFORE offer generation so its
    // m-line lands in the SDP.
    let mut change = rtc.sdp_api();
    let channel_id = change.add_channel("bitmule".into());
    let (offer, mut pending) = change
        .apply()
        .ok_or_else(|| anyhow!("sdp_api produced no offer — nothing added"))?;
    let mut next_timeout = drain_rtc(&mut rtc, &socket).await?;

    ws_send(&mut ws, &SignalFrame::Hello {
        role: Role::Sender.as_str().to_owned(),
        receiver_id: None,
    }).await?;

    let mut peer_hello_seen = false;
    let mut offer_holder: Option<SdpOffer> = Some(offer);
    let mut pending_holder: Option<_> = Some(pending);
    let mut opened = false;
    let mut buf = vec![0u8; 2000];

    while !opened {
        let dur = (next_timeout - Instant::now()).max(std::time::Duration::from_millis(1));

        tokio::select! {
            maybe_msg = ws.next() => {
                let frame = match parse_ws_frame(maybe_msg)? {
                    Some(f) => f,
                    None => continue,
                };
                match frame {
                    SignalFrame::Ice { candidate: Some(c) } => {
                        if let Some(remote) = parse_ice_candidate(&c).await {
                            rtc.add_remote_candidate(remote);
                            next_timeout = drain_rtc_capture_open(&mut rtc, &socket, channel_id, &mut opened).await?;
                        }
                    }
                    SignalFrame::PeerHello { .. } if !peer_hello_seen => {
                        peer_hello_seen = true;
                        let offer = offer_holder.take().expect("offer set on entry");
                        ws_send(&mut ws, &SignalFrame::Sdp {
                            kind: "offer".into(),
                            sdp: offer.to_sdp_string(),
                        }).await?;
                        debug!("offer sent");
                    }
                    SignalFrame::Sdp { kind, sdp } if kind == "answer" => {
                        let ans = SdpAnswer::from_sdp_string(&sdp)
                            .map_err(|e| anyhow!("parse answer: {e}"))?;
                        let pending_taken = pending_holder.take().expect("pending set on entry");
                        rtc.sdp_api().accept_answer(pending_taken, ans)
                            .map_err(|e| anyhow!("accept_answer: {e}"))?;
                        next_timeout = drain_rtc_capture_open(&mut rtc, &socket, channel_id, &mut opened).await?;
                    }
                    _ => {}
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
                next_timeout = drain_rtc_capture_open(&mut rtc, &socket, channel_id, &mut opened).await?;
            }

            _ = tokio::time::sleep(dur) => {
                rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("handle_input timeout: {e}"))?;
                next_timeout = drain_rtc_capture_open(&mut rtc, &socket, channel_id, &mut opened).await?;
            }
        }
    }
    info!("sender data channel open");
    Ok(LiveSession { session_id, role: Role::Sender, rtc, socket, ws, channel_id })
}

/// Receiver entry point — passive side: send hello + peer_hello, wait
/// for offer, produce + send answer, run loop until ChannelOpen (which
/// carries the id str0m assigned on the passive side).
pub async fn recv_connect(server_url: &str, session_id: SessionId) -> Result<LiveSession> {
    let session_hex = session_id.as_hex();
    info!(session = %session_hex, "opening receiver WS + Rtc");

    let mut ws = crate::open_ws(server_url, &session_hex).await?;
    let (mut rtc, socket) = build_rtc().await?;
    let mut next_timeout = drain_rtc(&mut rtc, &socket).await?;

    let receiver_id = SessionId::random().as_hex();
    ws_send(&mut ws, &SignalFrame::Hello {
        role: Role::Receiver.as_str().to_owned(),
        receiver_id: Some(receiver_id.clone()),
    }).await?;
    ws_send(&mut ws, &SignalFrame::PeerHello { receiver_id: Some(receiver_id) }).await?;

    let mut opened: Option<ChannelId> = None;
    let mut buf = vec![0u8; 2000];

    while opened.is_none() {
        let dur = (next_timeout - Instant::now()).max(std::time::Duration::from_millis(1));

        tokio::select! {
            maybe_msg = ws.next() => {
                let frame = match parse_ws_frame(maybe_msg)? {
                    Some(f) => f,
                    None => continue,
                };
                match frame {
                    SignalFrame::Ice { candidate: Some(c) } => {
                        if let Some(remote) = parse_ice_candidate(&c).await {
                            rtc.add_remote_candidate(remote);
                            next_timeout = drain_rtc_capture_id(&mut rtc, &socket, &mut opened).await?;
                        }
                    }
                    SignalFrame::Sdp { kind, sdp } if kind == "offer" => {
                        let offer = SdpOffer::from_sdp_string(&sdp)
                            .map_err(|e| anyhow!("parse offer: {e}"))?;
                        let answer = rtc.sdp_api().accept_offer(offer)
                            .map_err(|e| anyhow!("accept_offer: {e}"))?;
                        ws_send(&mut ws, &SignalFrame::Sdp {
                            kind: "answer".into(),
                            sdp: answer.to_sdp_string(),
                        }).await?;
                        debug!("answer sent");
                        next_timeout = drain_rtc_capture_id(&mut rtc, &socket, &mut opened).await?;
                    }
                    _ => {}
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
                next_timeout = drain_rtc_capture_id(&mut rtc, &socket, &mut opened).await?;
            }

            _ = tokio::time::sleep(dur) => {
                rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("handle_input timeout: {e}"))?;
                next_timeout = drain_rtc_capture_id(&mut rtc, &socket, &mut opened).await?;
            }
        }
    }

    let channel_id = opened.unwrap();
    info!("receiver data channel open (id={:?})", channel_id);
    Ok(LiveSession { session_id, role: Role::Receiver, rtc, socket, ws, channel_id })
}

// ---- file transfer over the data channel --------------------------------

/// Receive a single file over the opened WebRTC data channel using the
/// browser-parity wire framing:
/// - text frame: `{"type":"meta", name, size, chunkBytes, totalChunks}`
/// - binary frames: raw chunk payloads
/// - text frame: `{"type":"done"}` — sender signals end-of-file
///
/// Writes into `out_dir/<sanitized-name>` and returns the final path.
/// Blocks the LiveSession's rtc + socket + ws for the duration of the
/// transfer: incoming DTLS/SCTP packets are still pumped, ICE state is
/// still maintained, and any inbound signaling frames are drained but
/// otherwise ignored (post-open ICE trickle is silently applied).
pub async fn recv_file_over_dc(
    session: &mut LiveSession,
    out_dir: &Path,
    mut on_progress: impl FnMut(u64, u64, &str) + Send,
) -> Result<PathBuf> {
    tokio::fs::create_dir_all(out_dir)
        .await
        .with_context(|| format!("mkdir -p {}", out_dir.display()))?;

    let mut meta_opt: Option<MetaFrame> = None;
    let mut file_opt: Option<tokio::fs::File> = None;
    let mut path_opt: Option<PathBuf> = None;
    let mut received: u64 = 0;
    let mut done = false;
    let mut buf = vec![0u8; 2000];

    let mut next_timeout = drain_rtc_capture_data(
        &mut session.rtc, &session.socket, session.channel_id,
        &mut meta_opt, &mut file_opt, &mut path_opt, &mut received, &mut done, &mut on_progress, out_dir,
    ).await?;

    while !done {
        let dur = (next_timeout - Instant::now()).max(std::time::Duration::from_millis(1));

        tokio::select! {
            // Inbound signaling — post-open trickle etc. Apply ICE, ignore the rest.
            maybe_msg = session.ws.next() => {
                let frame = match parse_ws_frame(maybe_msg)? {
                    Some(f) => f,
                    None => continue,
                };
                if let SignalFrame::Ice { candidate: Some(c) } = frame {
                    if let Some(remote) = parse_ice_candidate(&c).await {
                        session.rtc.add_remote_candidate(remote);
                        next_timeout = drain_rtc_capture_data(
                            &mut session.rtc, &session.socket, session.channel_id,
                            &mut meta_opt, &mut file_opt, &mut path_opt, &mut received, &mut done, &mut on_progress, out_dir,
                        ).await?;
                    }
                }
            }

            r = session.socket.recv_from(&mut buf) => {
                let (n, source) = r.context("udp recv_from")?;
                let local = session.socket.local_addr().context("local_addr")?;
                let input = Input::Receive(Instant::now(), Receive {
                    proto: Protocol::Udp,
                    source,
                    destination: local,
                    contents: (&buf[..n]).try_into().map_err(|_| anyhow!("packet oversize"))?,
                });
                session.rtc.handle_input(input).map_err(|e| anyhow!("handle_input recv: {e}"))?;
                next_timeout = drain_rtc_capture_data(
                    &mut session.rtc, &session.socket, session.channel_id,
                    &mut meta_opt, &mut file_opt, &mut path_opt, &mut received, &mut done, &mut on_progress, out_dir,
                ).await?;
            }

            _ = tokio::time::sleep(dur) => {
                session.rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("handle_input timeout: {e}"))?;
                next_timeout = drain_rtc_capture_data(
                    &mut session.rtc, &session.socket, session.channel_id,
                    &mut meta_opt, &mut file_opt, &mut path_opt, &mut received, &mut done, &mut on_progress, out_dir,
                ).await?;
            }
        }
    }

    if let Some(mut f) = file_opt {
        f.flush().await?;
        f.sync_all().await?;
    }
    path_opt.ok_or_else(|| anyhow!("no meta received before done"))
}

/// Drain variant that dispatches Event::ChannelData(id, ..) into the
/// receiver's file-writer state. Text frames carry meta / done control;
/// binary frames are chunk payloads. Other events (ICE, ChannelOpen for
/// other channels, buffered-amount-low) are treated as generic.
#[allow(clippy::too_many_arguments)]
async fn drain_rtc_capture_data(
    rtc: &mut Rtc,
    socket: &UdpSocket,
    expected_channel: ChannelId,
    meta_opt: &mut Option<MetaFrame>,
    file_opt: &mut Option<tokio::fs::File>,
    path_opt: &mut Option<PathBuf>,
    received: &mut u64,
    done: &mut bool,
    on_progress: &mut (dyn FnMut(u64, u64, &str) + Send),
    out_dir: &Path,
) -> Result<Instant> {
    loop {
        match rtc.poll_output().map_err(|e| anyhow!("poll_output: {e}"))? {
            Output::Timeout(t) => return Ok(t),
            Output::Transmit(t) => {
                socket.send_to(&t.contents, t.destination).await
                    .with_context(|| format!("send_to {}", t.destination))?;
            }
            Output::Event(Event::ChannelData(ChannelData { id, binary, data })) if id == expected_channel => {
                if binary {
                    if let Some(f) = file_opt.as_mut() {
                        f.write_all(&data).await.context("write chunk")?;
                        *received += data.len() as u64;
                        if let Some(m) = meta_opt.as_ref() {
                            on_progress(*received, m.size, &m.name);
                        }
                    } else {
                        warn!("binary chunk arrived before meta — dropping {} bytes", data.len());
                    }
                } else {
                    // Text control frame: meta or done.
                    let text = match std::str::from_utf8(&data) {
                        Ok(s) => s,
                        Err(_) => { warn!("non-utf8 text frame"); continue; }
                    };
                    let val: serde_json::Value = match serde_json::from_str(text) {
                        Ok(v) => v,
                        Err(_) => { warn!("bad text frame: {text}"); continue; }
                    };
                    match val.get("type").and_then(|x| x.as_str()) {
                        Some("meta") => {
                            match serde_json::from_value::<MetaFrame>(val) {
                                Ok(m) => {
                                    let name = crate::sanitize_filename(&m.name);
                                    let path = out_dir.join(&name);
                                    let file = tokio::fs::File::create(&path).await
                                        .with_context(|| format!("create {}", path.display()))?;
                                    on_progress(0, m.size, &m.name);
                                    *file_opt = Some(file);
                                    *path_opt = Some(path);
                                    *meta_opt = Some(m);
                                }
                                Err(e) => warn!("meta decode: {e}"),
                            }
                        }
                        Some("done") => { *done = true; }
                        _ => {}
                    }
                }
            }
            Output::Event(e) => handle_generic_event(&e)?,
        }
    }
}

// ---- run-loop core ------------------------------------------------------

/// Drain poll_output until Timeout. Bail on ICE disconnect. Other events
/// are logged and discarded (callers use `drain_rtc_capture_open` or
/// `drain_rtc_capture_id` when they care about ChannelOpen specifically).
async fn drain_rtc(rtc: &mut Rtc, socket: &UdpSocket) -> Result<Instant> {
    loop {
        match rtc.poll_output().map_err(|e| anyhow!("poll_output: {e}"))? {
            Output::Timeout(t) => return Ok(t),
            Output::Transmit(t) => {
                socket.send_to(&t.contents, t.destination).await
                    .with_context(|| format!("send_to {}", t.destination))?;
            }
            Output::Event(e) => handle_generic_event(&e)?,
        }
    }
}

/// Drain variant used by send_connect: knows the expected channel id up
/// front (str0m assigns it when we call `add_channel`) and flips `opened`
/// when ChannelOpen for it fires.
async fn drain_rtc_capture_open(
    rtc: &mut Rtc,
    socket: &UdpSocket,
    expected: ChannelId,
    opened: &mut bool,
) -> Result<Instant> {
    loop {
        match rtc.poll_output().map_err(|e| anyhow!("poll_output: {e}"))? {
            Output::Timeout(t) => return Ok(t),
            Output::Transmit(t) => {
                socket.send_to(&t.contents, t.destination).await
                    .with_context(|| format!("send_to {}", t.destination))?;
            }
            Output::Event(Event::ChannelOpen(id, _label)) if id == expected => {
                *opened = true;
            }
            Output::Event(e) => handle_generic_event(&e)?,
        }
    }
}

/// Drain variant used by recv_connect: str0m assigns the channel id on
/// the passive side, so we discover it via the ChannelOpen event.
async fn drain_rtc_capture_id(
    rtc: &mut Rtc,
    socket: &UdpSocket,
    opened: &mut Option<ChannelId>,
) -> Result<Instant> {
    loop {
        match rtc.poll_output().map_err(|e| anyhow!("poll_output: {e}"))? {
            Output::Timeout(t) => return Ok(t),
            Output::Transmit(t) => {
                socket.send_to(&t.contents, t.destination).await
                    .with_context(|| format!("send_to {}", t.destination))?;
            }
            Output::Event(Event::ChannelOpen(id, _label)) => {
                *opened = Some(id);
            }
            Output::Event(e) => handle_generic_event(&e)?,
        }
    }
}

fn handle_generic_event(e: &Event) -> Result<()> {
    if let Event::IceConnectionStateChange(IceConnectionState::Disconnected) = e {
        bail!("ICE disconnected");
    }
    debug!("str0m event: {:?}", e);
    Ok(())
}

// ---- helpers ------------------------------------------------------------

async fn ws_send(ws: &mut Ws, frame: &SignalFrame) -> Result<()> {
    let text = serde_json::to_string(frame).context("frame encode")?;
    ws.send(Message::Text(text.into())).await.context("ws send")?;
    Ok(())
}

/// Decode a single tungstenite result into an optional SignalFrame.
/// Returns Ok(None) for non-text frames + parse failures (silent skip),
/// bails on stream close or transport error (both mean the session is
/// dead).
fn parse_ws_frame(msg: Option<Result<Message, tokio_tungstenite::tungstenite::Error>>) -> Result<Option<SignalFrame>> {
    let text = match msg {
        Some(Ok(Message::Text(t))) => t.to_string(),
        Some(Ok(Message::Close(_))) | None => bail!("ws closed pre-channel-open"),
        Some(Err(e)) => bail!("ws recv: {e}"),
        _ => return Ok(None),
    };
    Ok(serde_json::from_str(&text).ok())
}

/// Parse a browser-style ICE candidate JSON blob into a str0m Candidate.
/// mDNS `.local` addresses are resolved via [`crate::maybe_resolve_mdns_candidate`]
/// before being handed to str0m; if resolution fails the candidate is dropped
/// (the peer usually also emits a srflx candidate we can pair with).
async fn parse_ice_candidate(v: &serde_json::Value) -> Option<Candidate> {
    let line = v.get("candidate")?.as_str()?;
    if line.is_empty() { return None; }
    let resolved: String = if line.split_whitespace().nth(4).map_or(false, |a| a.ends_with(".local")) {
        match crate::maybe_resolve_mdns_candidate(line).await {
            Some(r) => r,
            None => {
                debug!("dropping unresolvable mdns ICE candidate");
                return None;
            }
        }
    } else {
        line.to_string()
    };
    match Candidate::from_sdp_string(&resolved) {
        Ok(c) => Some(c),
        Err(e) => { warn!("bad ice candidate: {e}"); None }
    }
}
