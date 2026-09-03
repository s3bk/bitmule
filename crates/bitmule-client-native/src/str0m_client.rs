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

use std::{collections::HashMap, net::{IpAddr, SocketAddr}, path::{Path, PathBuf}, sync::Arc, time::Instant};

use anyhow::{anyhow, bail, Context, Result};
use bitmule_core::SessionId;
use futures_util::{SinkExt, StreamExt};
use str0m::{
    change::{SdpAnswer, SdpOffer},
    channel::{ChannelData, ChannelId},
    net::{Protocol, Receive},
    Candidate, Event, IceConnectionState, Input, Output, Rtc,
};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::UdpSocket, sync::mpsc};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::{MetaFrame, Role, SignalFrame, Ws};
use crate::crypto::{BulkKey, Ephemeral, MetaKey, ShareKey, WrapKey};

/// A single received UDP packet — its bytes, source, and (critically)
/// the SPECIFIC local socket address it was delivered to. str0m's ICE
/// agent tracks known local candidates by their bound address, so we
/// need per-interface accuracy on the destination field or it drops
/// the packet as "unknown interface" (observed 2026-09-02 on Seb's box).
pub struct PoolRecv {
    pub bytes: Vec<u8>,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

/// One UdpSocket per host-candidate interface, all bound to the SAME
/// port. Recv is fan-in via a shared mpsc — per-socket recv-loop tasks
/// forward every packet with the destination correctly set to the bound
/// address of the socket that received it. Send routes by source IP:
/// str0m's Transmit outputs carry `source: SocketAddr` and we dispatch
/// to the matching socket so the outbound src-address matches the local
/// candidate str0m thinks it's using.
pub struct SocketPool {
    sockets: HashMap<IpAddr, Arc<UdpSocket>>,
    recv_rx: mpsc::UnboundedReceiver<PoolRecv>,
    _recv_tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl SocketPool {
    /// Async recv over ALL sockets in the pool via the shared mpsc.
    pub async fn recv(&mut self) -> Option<PoolRecv> {
        self.recv_rx.recv().await
    }

    /// Send to `dest` from the socket bound to `source_ip`. If no socket
    /// matches, falls back to the first available socket + logs a warning
    /// (indicates a str0m Transmit for a source we didn't bind).
    pub async fn send_from(&self, source: SocketAddr, dest: SocketAddr, bytes: &[u8]) -> Result<()> {
        let sock = match self.sockets.get(&source.ip()) {
            Some(s) => s.clone(),
            None => {
                warn!("no socket for source IP {} — falling back to any", source.ip());
                self.sockets.values().next().cloned()
                    .ok_or_else(|| anyhow!("socket pool is empty"))?
            }
        };
        sock.send_to(bytes, dest).await
            .with_context(|| format!("send_to {dest}"))?;
        Ok(())
    }

    /// Every socket's bound address, for logging + advertising.
    pub fn bound_addrs(&self) -> Vec<SocketAddr> {
        self.sockets.values()
            .filter_map(|s| s.local_addr().ok())
            .collect()
    }
}

/// A live str0m-backed session. Owner holds the Rtc + its socket pool +
/// the signaling WS.
pub struct LiveSession {
    pub session_id: SessionId,
    pub role: Role,
    pub rtc: Rtc,
    pub pool: SocketPool,
    pub ws: Ws,
    pub channel_id: ChannelId,
    /// Session AEAD key derived from HKDF(S, salt=session_id,
    /// "transfer-v1 wrap-key"). Both sides derive identically after
    /// the KEX-over-WS handshake completes.
    pub wrap_key: WrapKey,
    /// Session AEAD key derived from HKDF(S, salt=session_id,
    /// "transfer-v1 meta-key"). Distinct from wrap_key so a break of
    /// one doesn't propagate.
    pub meta_key: MetaKey,
    /// Bulk stream key. Sender-of-file generates it; receiver-of-file
    /// gets it via KeyWrap after wrapping by wrap_key. `None` until
    /// the wrap frame lands on either side.
    pub bulk_key: Option<BulkKey>,
    /// URL secret A. Held here so post-decrypt commitment checks
    /// (send-initiated flow) can call `share_key.verify_data_commitment`.
    pub share_key: ShareKey,
}

/// Build a fresh Rtc + a SocketPool with one UdpSocket per host-candidate
/// interface. All sockets share the same port so ICE candidates all look
/// consistent to the remote peer. Per-socket recv-loop tasks fan into a
/// shared mpsc so the caller can select! on a single stream.
///
/// Fixes the "Discarding STUN request on unknown interface: 0.0.0.0:port"
/// bug (Seb 2026-09-02): binding once on 0.0.0.0 made socket.local_addr()
/// return the unspecified address, which str0m's ICE agent didn't
/// recognize as any known local candidate → drops. Per-IP sockets give
/// each recv a specific, matchable destination.
async fn build_rtc() -> Result<(Rtc, SocketPool)> {
    // Decide which IPs to bind on.
    let mut announced: Vec<IpAddr> = Vec::new();
    if let Ok(ip) = discover_outbound_ip().await {
        announced.push(ip);
    }
    for ip in local_interface_ips() {
        if !announced.contains(&ip) { announced.push(ip); }
    }
    if !announced.iter().any(|ip| ip.is_loopback()) {
        announced.push(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }
    if announced.is_empty() {
        announced.push(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }

    // Bind the first socket at (ip, 0) to get an OS-assigned port; then
    // bind each subsequent socket at that SAME port on its specific IP.
    // Linux allows same port on different specific IPs (each is a
    // distinct 5-tuple root), unlike 0.0.0.0:port + specific:port.
    let mut sockets: HashMap<IpAddr, Arc<UdpSocket>> = HashMap::new();
    let mut port: Option<u16> = None;
    for ip in &announced {
        let bind_addr = SocketAddr::new(*ip, port.unwrap_or(0));
        let sock = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!("bind {bind_addr} failed: {e} — skipping");
                continue;
            }
        };
        if port.is_none() {
            port = Some(sock.local_addr()?.port());
        }
        sockets.insert(*ip, Arc::new(sock));
    }
    if sockets.is_empty() {
        bail!("could not bind any UDP socket for host candidates");
    }
    let port = port.expect("at least one socket bound → port set");

    // Spawn one recv task per socket that forwards packets into the pool's mpsc.
    let (recv_tx, recv_rx) = mpsc::unbounded_channel::<PoolRecv>();
    let mut recv_tasks = Vec::new();
    for (ip, sock) in &sockets {
        let sock = sock.clone();
        let tx = recv_tx.clone();
        let dest = SocketAddr::new(*ip, port);
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, source)) => {
                        let pr = PoolRecv {
                            bytes: buf[..n].to_vec(),
                            source,
                            destination: dest,
                        };
                        if tx.send(pr).is_err() { break; }
                    }
                    Err(e) => {
                        warn!("recv task for {dest} exiting: {e}");
                        break;
                    }
                }
            }
        });
        recv_tasks.push(task);
    }
    drop(recv_tx);
    let pool = SocketPool { sockets, recv_rx, _recv_tasks: recv_tasks };

    let mut rtc = Rtc::new(Instant::now());
    for addr in pool.bound_addrs() {
        match Candidate::host(addr, "udp") {
            Ok(c) => { rtc.add_local_candidate(c); }
            Err(e) => warn!("skipping host candidate {addr}: {e}"),
        }
    }

    Ok((rtc, pool))
}

/// Enumerate local interface IPs by parsing `getifaddrs`-style output.
/// Falls back to empty on failure (build_rtc still has the outbound-IP
/// discovery + loopback fallback to cover the important cases).
fn local_interface_ips() -> Vec<std::net::IpAddr> {
    // Small no-extra-dep read of /proc/net/if_inet6 + local socket bind
    // enumeration would be ideal; simplest correct thing without adding
    // a crate is to call `hostname -I` and parse. Skip on macOS/Windows.
    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = std::process::Command::new("hostname").arg("-I").output() {
            if out.status.success() {
                return String::from_utf8_lossy(&out.stdout)
                    .split_whitespace()
                    .filter_map(|s| s.parse().ok())
                    .collect();
            }
        }
    }
    Vec::new()
}

/// Find a routable local interface IP by opening a scratch UDP socket to
/// a public address (Google DNS) — no bytes are sent, the connect() call
/// just makes the OS pick the outbound interface. Falls back to
/// 127.0.0.1 for isolated/loopback-only test environments.
async fn discover_outbound_ip() -> Result<std::net::IpAddr> {
    let probe = UdpSocket::bind("0.0.0.0:0").await?;
    match probe.connect("8.8.8.8:80").await {
        Ok(()) => Ok(probe.local_addr()?.ip()),
        Err(_) => Ok(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    }
}

/// Sender entry point — active side: create data channel, produce offer,
/// send over WS, wait for answer, run loop until ChannelOpen.
pub async fn send_connect(server_url: &str, share_key: ShareKey) -> Result<LiveSession> {
    let session_hex = share_key.session_id_hex();
    let session_id = SessionId::from_hex(&session_hex)
        .map_err(|e| anyhow!("session_id from hex: {e}"))?;
    info!(session = %session_hex, "opening sender WS + Rtc");

    let mut ws = crate::open_ws(&websocket_url(server_url)?, &session_hex).await?;
    let (mut rtc, mut pool) = build_rtc().await?;

    // Active side: create the data channel BEFORE offer generation so its
    // m-line lands in the SDP.
    let mut change = rtc.sdp_api();
    let channel_id = change.add_channel("bitmule".into());
    let (offer, mut pending) = change
        .apply()
        .ok_or_else(|| anyhow!("sdp_api produced no offer — nothing added"))?;
    let mut next_timeout = drain_rtc(&mut rtc, &pool).await?;

    ws_send(&mut ws, &SignalFrame::Hello {
        role: Role::Sender.as_str().to_owned(),
        receiver_id: None,
    }).await?;

    // Crypto handshake — send our ephemeral immediately, wait for peer's
    // in the loop below (concurrent with SDP exchange).
    let local_ephemeral = Ephemeral::generate();
    let local_pub = local_ephemeral.public_bytes();
    let local_mac = share_key.mac_ephemeral_pub(&local_pub);
    ws_send(&mut ws, &SignalFrame::KexPub {
        pub_hex: hex_encode(&local_pub),
        mac_hex: hex_encode(&local_mac),
    }).await?;
    let mut ephemeral_holder = Some(local_ephemeral);
    let mut wrap_key: Option<WrapKey> = None;
    let mut meta_key: Option<MetaKey> = None;
    let mut bulk_key: Option<BulkKey> = None;
    let mut key_wrap_sent = false;
    let session_id_bytes: [u8; 32] = hex_decode_fixed(&session_hex)?;

    let mut peer_hello_seen = false;
    let mut offer_holder: Option<SdpOffer> = Some(offer);
    let mut pending_holder: Option<_> = Some(pending);
    let mut opened = false;
    let mut buf = vec![0u8; 4096];

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
                            next_timeout = drain_rtc_capture_open(&mut rtc, &pool, channel_id, &mut opened).await?;
                        }
                    }
                    SignalFrame::PeerHello { .. } if !peer_hello_seen => {
                        peer_hello_seen = true;
                        let offer = offer_holder.take().expect("offer set on entry");
                        let offer_sdp = offer.to_sdp_string();
                        info!("OFFER SDP:\n{}", offer_sdp);
                        ws_send(&mut ws, &SignalFrame::Sdp {
                            kind: "offer".into(),
                            sdp: offer_sdp,
                        }).await?;
                        debug!("offer sent");
                    }
                    SignalFrame::Sdp { kind, sdp } if kind == "answer" => {
                        info!("ANSWER SDP:\n{}", sdp);
                        let ans = SdpAnswer::from_sdp_string(&sdp)
                            .map_err(|e| anyhow!("parse answer: {e}"))?;
                        let pending_taken = pending_holder.take().expect("pending set on entry");
                        rtc.sdp_api().accept_answer(pending_taken, ans)
                            .map_err(|e| anyhow!("accept_answer: {e}"))?;
                        next_timeout = drain_rtc_capture_open(&mut rtc, &pool, channel_id, &mut opened).await?;
                    }
                    SignalFrame::KexPub { pub_hex, mac_hex } => {
                        if wrap_key.is_some() {
                            warn!("duplicate KexPub from peer — ignoring");
                            continue;
                        }
                        let peer_pub = hex_decode_fixed::<32>(&pub_hex)?;
                        let peer_mac = hex_decode_fixed::<32>(&mac_hex)?;
                        let expected_mac = share_key.mac_ephemeral_pub(&peer_pub);
                        if !constant_time_eq_bytes(&expected_mac, &peer_mac) {
                            bail!("KexPub MAC verify failed — peer does not know the share key");
                        }
                        let eph = ephemeral_holder.take()
                            .ok_or_else(|| anyhow!("local ephemeral gone before peer KexPub arrived"))?;
                        let s = eph.derive_shared_secret(&peer_pub)?;
                        wrap_key = Some(s.wrap_key(&session_id_bytes));
                        meta_key = Some(s.meta_key(&session_id_bytes));
                        info!("KEX complete — wrap_key + meta_key derived");
                    }
                    _ => {}
                }
            }

            maybe_pr = pool.recv() => {
                let pr = maybe_pr.ok_or_else(|| anyhow!("pool recv closed"))?;
                info!("RX ← {} → {} ({} bytes)", pr.source, pr.destination, pr.bytes.len());
                let input = Input::Receive(Instant::now(), Receive {
                    proto: Protocol::Udp,
                    source: pr.source,
                    destination: pr.destination,
                    contents: pr.bytes.as_slice().try_into().map_err(|_| anyhow!("packet oversize"))?,
                });
                rtc.handle_input(input).map_err(|e| anyhow!("handle_input recv: {e}"))?;
                next_timeout = drain_rtc_capture_open(&mut rtc, &pool, channel_id, &mut opened).await?;
            }

            _ = tokio::time::sleep(dur) => {
                rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("handle_input timeout: {e}"))?;
                next_timeout = drain_rtc_capture_open(&mut rtc, &pool, channel_id, &mut opened).await?;
            }
        }

        // Sender-side: as soon as wrap_key is derived, generate B, wrap it,
        // and send the KeyWrap over WS. Receiver decrypts + stores B.
        if wrap_key.is_some() && !key_wrap_sent {
            let b = BulkKey::random();
            let wk = wrap_key.as_ref().unwrap();
            let (nonce, ct) = wk.wrap_bulk_key(&b)?;
            ws_send(&mut ws, &SignalFrame::KeyWrap {
                enc_b_hex: hex_encode(&ct),
                nonce_hex: hex_encode(&nonce),
            }).await?;
            bulk_key = Some(b);
            key_wrap_sent = true;
            info!("bulk key generated + wrapped + sent");
        }
    }
    info!("sender data channel open");
    let wrap_key = wrap_key.ok_or_else(|| anyhow!("DC opened before KEX completed"))?;
    let meta_key = meta_key.ok_or_else(|| anyhow!("DC opened before KEX completed"))?;
    let bulk_key = bulk_key.ok_or_else(|| anyhow!("DC opened before bulk key was generated"))?;
    Ok(LiveSession {
        session_id, role: Role::Sender, rtc, pool, ws, channel_id,
        wrap_key, meta_key, bulk_key: Some(bulk_key), share_key,
    })
}

/// Receiver entry point — passive side: send hello + peer_hello, wait
/// for offer, produce + send answer, run loop until ChannelOpen (which
/// carries the id str0m assigned on the passive side).
pub async fn recv_connect(server_url: &str, share_key: ShareKey) -> Result<LiveSession> {
    let session_hex = share_key.session_id_hex();
    let session_id = SessionId::from_hex(&session_hex)
        .map_err(|e| anyhow!("session_id from hex: {e}"))?;
    info!(session = %session_hex, "opening receiver WS + Rtc");

    let mut ws = crate::open_ws(server_url, &session_hex).await?;
    let (mut rtc, mut pool) = build_rtc().await?;
    let mut next_timeout = drain_rtc(&mut rtc, &pool).await?;

    let receiver_id = SessionId::random().as_hex();
    ws_send(&mut ws, &SignalFrame::Hello {
        role: Role::Receiver.as_str().to_owned(),
        receiver_id: Some(receiver_id.clone()),
    }).await?;
    ws_send(&mut ws, &SignalFrame::PeerHello { receiver_id: Some(receiver_id) }).await?;

    // Crypto handshake — same symmetric KEX as send_connect.
    let local_ephemeral = Ephemeral::generate();
    let local_pub = local_ephemeral.public_bytes();
    let local_mac = share_key.mac_ephemeral_pub(&local_pub);
    ws_send(&mut ws, &SignalFrame::KexPub {
        pub_hex: hex_encode(&local_pub),
        mac_hex: hex_encode(&local_mac),
    }).await?;
    let mut ephemeral_holder = Some(local_ephemeral);
    let mut wrap_key: Option<WrapKey> = None;
    let mut meta_key: Option<MetaKey> = None;
    let mut bulk_key: Option<BulkKey> = None;
    let session_id_bytes: [u8; 32] = hex_decode_fixed(&session_hex)?;

    let mut opened: Option<ChannelId> = None;
    let mut buf = vec![0u8; 4096];

    while opened.is_none() || bulk_key.is_none() {
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
                            next_timeout = drain_rtc_capture_id(&mut rtc, &pool, &mut opened).await?;
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
                        next_timeout = drain_rtc_capture_id(&mut rtc, &pool, &mut opened).await?;
                    }
                    SignalFrame::KexPub { pub_hex, mac_hex } => {
                        if wrap_key.is_some() {
                            warn!("duplicate KexPub from peer — ignoring");
                            continue;
                        }
                        let peer_pub = hex_decode_fixed::<32>(&pub_hex)?;
                        let peer_mac = hex_decode_fixed::<32>(&mac_hex)?;
                        let expected_mac = share_key.mac_ephemeral_pub(&peer_pub);
                        if !constant_time_eq_bytes(&expected_mac, &peer_mac) {
                            bail!("KexPub MAC verify failed — peer does not know the share key");
                        }
                        let eph = ephemeral_holder.take()
                            .ok_or_else(|| anyhow!("local ephemeral gone before peer KexPub arrived"))?;
                        let s = eph.derive_shared_secret(&peer_pub)?;
                        wrap_key = Some(s.wrap_key(&session_id_bytes));
                        meta_key = Some(s.meta_key(&session_id_bytes));
                        info!("KEX complete — wrap_key + meta_key derived");
                    }
                    SignalFrame::KeyWrap { enc_b_hex, nonce_hex } => {
                        let wk = wrap_key.as_ref()
                            .ok_or_else(|| anyhow!("KeyWrap arrived before KEX complete"))?;
                        let nonce = hex_decode_var(&nonce_hex)?;
                        let ct = hex_decode_var(&enc_b_hex)?;
                        bulk_key = Some(wk.unwrap_bulk_key(&nonce, &ct)?);
                        info!("bulk key received + unwrapped");
                    }
                    _ => {}
                }
            }

            maybe_pr = pool.recv() => {
                let pr = maybe_pr.ok_or_else(|| anyhow!("pool recv closed"))?;
                info!("RX ← {} → {} ({} bytes)", pr.source, pr.destination, pr.bytes.len());
                let input = Input::Receive(Instant::now(), Receive {
                    proto: Protocol::Udp,
                    source: pr.source,
                    destination: pr.destination,
                    contents: pr.bytes.as_slice().try_into().map_err(|_| anyhow!("packet oversize"))?,
                });
                rtc.handle_input(input).map_err(|e| anyhow!("handle_input recv: {e}"))?;
                next_timeout = drain_rtc_capture_id(&mut rtc, &pool, &mut opened).await?;
            }

            _ = tokio::time::sleep(dur) => {
                rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("handle_input timeout: {e}"))?;
                next_timeout = drain_rtc_capture_id(&mut rtc, &pool, &mut opened).await?;
            }
        }
    }

    let channel_id = opened.unwrap();
    info!("receiver data channel open (id={:?})", channel_id);
    let wrap_key = wrap_key.ok_or_else(|| anyhow!("exited handshake loop without KEX complete"))?;
    let meta_key = meta_key.ok_or_else(|| anyhow!("exited handshake loop without KEX complete"))?;
    let bulk_key = bulk_key.ok_or_else(|| anyhow!("exited handshake loop without bulk key"))?;
    Ok(LiveSession {
        session_id, role: Role::Receiver, rtc, pool, ws, channel_id,
        wrap_key, meta_key, bulk_key: Some(bulk_key), share_key,
    })
}

// ---- file transfer over the data channel --------------------------------

const CHUNK_BYTES: usize = 16 * 1024;
const BUFFERED_LOW_THRESHOLD: usize = 1 * 1024 * 1024;

/// Send a file over the opened WebRTC data channel using the browser-parity
/// wire framing (see [`recv_file_over_dc`]).
///
/// Backpressure: str0m's `channel.write()` returns Ok(false) when the SCTP
/// send buffer can't accept the payload. We set the buffered-amount-low
/// threshold to 1 MiB, and on a rejected write we keep pumping the run
/// loop (which drives SCTP and fires ChannelBufferedAmountLow when it's
/// safe to try again) until the write is accepted.
pub async fn send_file_over_dc(
    session: &mut LiveSession,
    file_path: &Path,
    mut on_progress: impl FnMut(u64, u64) + Send,
) -> Result<()> {
    let meta_stat = tokio::fs::metadata(file_path).await
        .with_context(|| format!("stat {}", file_path.display()))?;
    if !meta_stat.is_file() {
        bail!("{} is not a regular file", file_path.display());
    }
    let size = meta_stat.len();
    let name = file_path.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".to_string());
    let total_chunks = if size == 0 { 0 } else { (size + CHUNK_BYTES as u64 - 1) / CHUNK_BYTES as u64 };

    let meta_json = serde_json::json!({
        "type": "meta",
        "name": name,
        "size": size,
        "chunkBytes": CHUNK_BYTES,
        "totalChunks": total_chunks,
    }).to_string();

    // Set the flow-control threshold once, then send meta as a text frame.
    channel_set_low_threshold(&mut session.rtc, session.channel_id, BUFFERED_LOW_THRESHOLD)?;
    channel_write_all(session, false, meta_json.as_bytes()).await?;

    let mut f = tokio::fs::File::open(file_path).await
        .with_context(|| format!("open {}", file_path.display()))?;
    let mut sent: u64 = 0;
    let mut buf = vec![0u8; CHUNK_BYTES];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 { break; }
        channel_write_all(session, true, &buf[..n]).await?;
        sent += n as u64;
        on_progress(sent, size);
    }

    // Done marker + drain the SCTP queue before returning (caller closing
    // the session immediately after should not cut the tail).
    channel_write_all(session, false, br#"{"type":"done"}"#).await?;
    drain_until_buffer_empty(session).await?;
    Ok(())
}

/// Write `buf` (text or binary) to the session's data channel, awaiting
/// backpressure if the SCTP buffer is full. Every write is followed by a
/// drain per str0m's single-mutation invariant.
async fn channel_write_all(
    session: &mut LiveSession,
    binary: bool,
    buf: &[u8],
) -> Result<()> {
    let mut next_timeout = drain_rtc(&mut session.rtc, &session.pool).await?;
    let mut recv_buf = vec![0u8; 4096];

    loop {
        let accepted = {
            let mut ch = session.rtc.channel(session.channel_id)
                .ok_or_else(|| anyhow!("channel {:?} gone", session.channel_id))?;
            ch.write(binary, buf).map_err(|e| anyhow!("channel write: {e}"))?
        };
        if accepted {
            next_timeout = drain_rtc(&mut session.rtc, &session.pool).await?;
            let _ = next_timeout;
            return Ok(());
        }

        // Buffer full — pump one iteration of the run loop to let SCTP
        // drain, then retry. This is the same select! shape as the
        // connect loops but scoped to a single wait-tick.
        let dur = (next_timeout - Instant::now()).max(std::time::Duration::from_millis(1));
        tokio::select! {
            maybe_msg = session.ws.next() => {
                let frame = match parse_ws_frame(maybe_msg)? {
                    Some(f) => f,
                    None => continue,
                };
                if let SignalFrame::Ice { candidate: Some(c) } = frame {
                    if let Some(remote) = parse_ice_candidate(&c).await {
                        session.rtc.add_remote_candidate(remote);
                        next_timeout = drain_rtc(&mut session.rtc, &session.pool).await?;
                    }
                }
            }
            maybe_pr = session.pool.recv() => {
                let pr = maybe_pr.ok_or_else(|| anyhow!("pool recv closed"))?;
                info!("RX ← {} → {} ({} bytes)", pr.source, pr.destination, pr.bytes.len());
                let input = Input::Receive(Instant::now(), Receive {
                    proto: Protocol::Udp,
                    source: pr.source,
                    destination: pr.destination,
                    contents: pr.bytes.as_slice().try_into().map_err(|_| anyhow!("packet oversize"))?,
                });
                session.rtc.handle_input(input).map_err(|e| anyhow!("handle_input recv: {e}"))?;
                next_timeout = drain_rtc(&mut session.rtc, &session.pool).await?;
            }
            _ = tokio::time::sleep(dur) => {
                session.rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("handle_input timeout: {e}"))?;
                next_timeout = drain_rtc(&mut session.rtc, &session.pool).await?;
            }
        }
    }
}

/// Set the SCTP buffered-amount-low threshold on the session's channel,
/// then drain per str0m's invariant.
fn channel_set_low_threshold(rtc: &mut Rtc, id: ChannelId, threshold: usize) -> Result<()> {
    let mut ch = rtc.channel(id).ok_or_else(|| anyhow!("channel {:?} gone", id))?;
    ch.set_buffered_amount_low_threshold(threshold);
    // Note: set_buffered_amount_low_threshold takes &mut self but doesn't
    // return a Result and isn't itself listed as a "mutation" in str0m's
    // README enumeration. We still drain in the caller (channel_write_all)
    // via its initial drain_rtc call — safe.
    Ok(())
}

/// Keep pumping the run loop until the send buffer drains to 0. Used by
/// send_file_over_dc after the "done" frame so callers can drop the
/// session cleanly without truncating the tail.
async fn drain_until_buffer_empty(session: &mut LiveSession) -> Result<()> {
    let mut next_timeout = drain_rtc(&mut session.rtc, &session.pool).await?;
    let mut recv_buf = vec![0u8; 4096];
    loop {
        let buffered = {
            let mut ch = session.rtc.channel(session.channel_id)
                .ok_or_else(|| anyhow!("channel gone"))?;
            ch.buffered_amount()
        };
        if buffered == 0 { return Ok(()); }

        let dur = (next_timeout - Instant::now()).max(std::time::Duration::from_millis(1));
        tokio::select! {
            maybe_pr = session.pool.recv() => {
                let pr = maybe_pr.ok_or_else(|| anyhow!("pool recv closed"))?;
                info!("RX ← {} → {} ({} bytes)", pr.source, pr.destination, pr.bytes.len());
                let input = Input::Receive(Instant::now(), Receive {
                    proto: Protocol::Udp,
                    source: pr.source,
                    destination: pr.destination,
                    contents: pr.bytes.as_slice().try_into().map_err(|_| anyhow!("packet oversize"))?,
                });
                session.rtc.handle_input(input).map_err(|e| anyhow!("handle_input recv: {e}"))?;
                next_timeout = drain_rtc(&mut session.rtc, &session.pool).await?;
            }
            _ = tokio::time::sleep(dur) => {
                session.rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("handle_input timeout: {e}"))?;
                next_timeout = drain_rtc(&mut session.rtc, &session.pool).await?;
            }
        }
    }
}

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
    let mut buf = vec![0u8; 4096];

    let mut next_timeout = drain_rtc_capture_data(
        &mut session.rtc, &session.pool, session.channel_id,
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
                            &mut session.rtc, &session.pool, session.channel_id,
                            &mut meta_opt, &mut file_opt, &mut path_opt, &mut received, &mut done, &mut on_progress, out_dir,
                        ).await?;
                    }
                }
            }

            maybe_pr = session.pool.recv() => {
                let pr = maybe_pr.ok_or_else(|| anyhow!("pool recv closed"))?;
                info!("RX ← {} → {} ({} bytes)", pr.source, pr.destination, pr.bytes.len());
                let input = Input::Receive(Instant::now(), Receive {
                    proto: Protocol::Udp,
                    source: pr.source,
                    destination: pr.destination,
                    contents: pr.bytes.as_slice().try_into().map_err(|_| anyhow!("packet oversize"))?,
                });
                session.rtc.handle_input(input).map_err(|e| anyhow!("handle_input recv: {e}"))?;
                next_timeout = drain_rtc_capture_data(
                    &mut session.rtc, &session.pool, session.channel_id,
                    &mut meta_opt, &mut file_opt, &mut path_opt, &mut received, &mut done, &mut on_progress, out_dir,
                ).await?;
            }

            _ = tokio::time::sleep(dur) => {
                session.rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("handle_input timeout: {e}"))?;
                next_timeout = drain_rtc_capture_data(
                    &mut session.rtc, &session.pool, session.channel_id,
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
    pool: &SocketPool,
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
                info!("TX → {} ({} bytes)", t.destination, t.contents.len());
                pool.send_from(t.source, t.destination, &t.contents).await
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

// ---- top-level dispatchers (unify DC + relay per TransportMode) ---------

use crate::{TransportMode, WEBRTC_FALLBACK_MS};

fn websocket_url(http_url: &str) -> Result<String> {
    if let Some(rest) = http_url.strip_prefix("http://") {
        Ok(format!("ws://{rest}"))
    } else if let Some(rest) = http_url.strip_prefix("https://") {
        Ok(format!("wss://{rest}"))
    } else {
        bail!("invalid protocol")
    }
}

/// Send `file_path` over a fresh session. Dispatch by TransportMode:
/// - `Webrtc`: send_connect → send_file_over_dc.
/// - `Relay`: open a ws, spawn a pumper task, forward to send_file_over_relay.
/// - `Auto`: try Webrtc with `WEBRTC_FALLBACK_MS` deadline for the DC to
///   open; on timeout or error, fall back to Relay. Progress ticks from
///   the aborted WebRTC attempt are lost by the fallback — the relay
///   path starts from 0 on the retry.
pub async fn send_file(
    server_url_http: &str,
    share_key: ShareKey,
    file_path: &Path,
    mode: TransportMode,
    on_progress: impl FnMut(u64, u64) + Send,
) -> Result<()> {
    match mode {
        TransportMode::Webrtc => send_file_webrtc(server_url_http, share_key, file_path, on_progress).await,
        TransportMode::Relay => send_file_relay(server_url_http, share_key, file_path, on_progress).await,
        TransportMode::Auto => {
            let dur = std::time::Duration::from_millis(WEBRTC_FALLBACK_MS);
            // We split on_progress so the fallback retry has its own callback
            // clone. The progress fn is FnMut so we can't clone it directly;
            // wrap in Arc<Mutex<_>> and let each attempt call through.
            let progress = std::sync::Arc::new(tokio::sync::Mutex::new(on_progress));
            let webrtc_progress = progress.clone();
            let webrtc_fut = async {
                let mut sess = tokio::time::timeout(dur, send_connect(server_url_http, share_key.clone())).await
                    .map_err(|_| anyhow!("webrtc DC open exceeded {} ms", WEBRTC_FALLBACK_MS))??;
                send_file_over_dc(&mut sess, file_path, |a, b| {
                    if let Ok(mut g) = webrtc_progress.try_lock() { g(a, b); }
                }).await
            };
            match webrtc_fut.await {
                Ok(()) => Ok(()),
                Err(e) => {
                    warn!("webrtc path failed ({e}), falling back to relay");
                    let relay_progress = progress.clone();
                    send_file_relay(server_url_http, share_key, file_path, move |a, b| {
                        if let Ok(mut g) = relay_progress.try_lock() { g(a, b); }
                    }).await
                }
            }
        }
    }
}

/// Receive one file for `session_id`. Same dispatch shape as [`send_file`].
pub async fn recv_file(
    server_url_http: &str,
    share_key: ShareKey,
    out_dir: &Path,
    mode: TransportMode,
    on_progress: impl FnMut(u64, u64, &str) + Send,
) -> Result<PathBuf> {
    match mode {
        TransportMode::Webrtc => recv_file_webrtc(server_url_http, share_key, out_dir, on_progress).await,
        TransportMode::Relay => recv_file_relay(server_url_http, share_key, out_dir, on_progress).await,
        TransportMode::Auto => {
            let dur = std::time::Duration::from_millis(WEBRTC_FALLBACK_MS);
            let progress = std::sync::Arc::new(tokio::sync::Mutex::new(on_progress));
            let webrtc_progress = progress.clone();
            let webrtc_fut = async {
                let mut sess = tokio::time::timeout(dur, recv_connect(server_url_http, share_key.clone())).await
                    .map_err(|_| anyhow!("webrtc DC open exceeded {} ms", WEBRTC_FALLBACK_MS))??;
                recv_file_over_dc(&mut sess, out_dir, |a, b, n| {
                    if let Ok(mut g) = webrtc_progress.try_lock() { g(a, b, n); }
                }).await
            };
            match webrtc_fut.await {
                Ok(p) => Ok(p),
                Err(e) => {
                    warn!("webrtc path failed ({e}), falling back to relay");
                    let relay_progress = progress.clone();
                    recv_file_relay(server_url_http, share_key, out_dir, move |a, b, n| {
                        if let Ok(mut g) = relay_progress.try_lock() { g(a, b, n); }
                    }).await
                }
            }
        }
    }
}

// One-shot helpers per transport — avoid repeating the wire-up.

async fn send_file_webrtc(
    server_url_http: &str,
    share_key: ShareKey,
    file_path: &Path,
    on_progress: impl FnMut(u64, u64) + Send,
) -> Result<()> {
    let mut sess = send_connect(server_url_http, share_key).await?;
    send_file_over_dc(&mut sess, file_path, on_progress).await
}

async fn recv_file_webrtc(
    server_url_http: &str,
    share_key: ShareKey,
    out_dir: &Path,
    on_progress: impl FnMut(u64, u64, &str) + Send,
) -> Result<PathBuf> {
    let mut sess = recv_connect(server_url_http, share_key).await?;
    recv_file_over_dc(&mut sess, out_dir, on_progress).await
}

async fn send_file_relay(
    server_url_http: &str,
    share_key: ShareKey,
    file_path: &Path,
    on_progress: impl FnMut(u64, u64) + Send,
) -> Result<()> {
    let session_hex = share_key.session_id_hex();
    let session_id = SessionId::from_hex(&session_hex)
        .map_err(|e| anyhow!("session_id from hex: {e}"))?;
    let ws = crate::open_ws(server_url_http, &session_hex).await?;
    let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let (in_tx, _in_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let progress = std::sync::Arc::new(tokio::sync::Mutex::new(crate::RelaySendProgress::default()));
    let _pump = tokio::spawn(pump_relay_ws(ws, out_rx, in_tx));
    crate::send_file_over_relay(server_url_http, &session_id, file_path, out_tx, progress, on_progress).await
}

async fn recv_file_relay(
    server_url_http: &str,
    share_key: ShareKey,
    out_dir: &Path,
    on_progress: impl FnMut(u64, u64, &str) + Send,
) -> Result<PathBuf> {
    let session_hex = share_key.session_id_hex();
    let session_id = SessionId::from_hex(&session_hex)
        .map_err(|e| anyhow!("session_id from hex: {e}"))?;
    let ws = crate::open_ws(server_url_http, &session_hex).await?;
    let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let _pump = tokio::spawn(pump_relay_ws(ws, out_rx, in_tx));
    let _ = out_tx; // relay recv only reads; sender kept alive so pumper's send half stays valid
    crate::recv_file_over_relay(server_url_http, &session_id, out_dir, in_rx, on_progress).await
}

/// Simple ws pumper for the relay path — moves outgoing raw strings from
/// `out_rx` onto the ws, and forwards ws text frames into `in_tx`. Runs
/// until either side closes.
async fn pump_relay_ws(
    mut ws: Ws,
    mut out_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    in_tx: tokio::sync::mpsc::UnboundedSender<String>,
) {
    loop {
        tokio::select! {
            maybe_msg = ws.next() => {
                match maybe_msg {
                    Some(Ok(Message::Text(t))) => {
                        if in_tx.send(t.to_string()).is_err() { break; }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(e)) => { warn!("relay ws recv: {e}"); break; }
                    _ => {}
                }
            }
            maybe_out = out_rx.recv() => {
                let Some(text) = maybe_out else { break };
                if let Err(e) = ws.send(Message::Text(text.into())).await {
                    warn!("relay ws send: {e}");
                    break;
                }
            }
        }
    }
}

// ---- run-loop core ------------------------------------------------------

/// Drain poll_output until Timeout. Bail on ICE disconnect. Other events
/// are logged and discarded (callers use `drain_rtc_capture_open` or
/// `drain_rtc_capture_id` when they care about ChannelOpen specifically).
async fn drain_rtc(rtc: &mut Rtc, pool: &SocketPool) -> Result<Instant> {
    loop {
        match rtc.poll_output().map_err(|e| anyhow!("poll_output: {e}"))? {
            Output::Timeout(t) => return Ok(t),
            Output::Transmit(t) => {
                info!("TX → {} ({} bytes)", t.destination, t.contents.len());
                pool.send_from(t.source, t.destination, &t.contents).await
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
    pool: &SocketPool,
    expected: ChannelId,
    opened: &mut bool,
) -> Result<Instant> {
    loop {
        match rtc.poll_output().map_err(|e| anyhow!("poll_output: {e}"))? {
            Output::Timeout(t) => return Ok(t),
            Output::Transmit(t) => {
                info!("TX → {} ({} bytes)", t.destination, t.contents.len());
                pool.send_from(t.source, t.destination, &t.contents).await
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
    pool: &SocketPool,
    opened: &mut Option<ChannelId>,
) -> Result<Instant> {
    loop {
        match rtc.poll_output().map_err(|e| anyhow!("poll_output: {e}"))? {
            Output::Timeout(t) => return Ok(t),
            Output::Transmit(t) => {
                info!("TX → {} ({} bytes)", t.destination, t.contents.len());
                pool.send_from(t.source, t.destination, &t.contents).await
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
    // Bump to info! for the DTLS-handshake-debug pass (2026-09-02): we
    // want every connection-state + signaling-state + channel-open
    // transition surfaced without asking users to flip RUST_LOG.
    info!("str0m event: {:?}", e);
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
    if line.is_empty() {
        info!("remote ICE candidate: <end-of-candidates>");
        return None;
    }
    info!("remote ICE candidate: {line}");
    let resolved: String = if line.split_whitespace().nth(4).map_or(false, |a| a.ends_with(".local")) {
        match crate::maybe_resolve_mdns_candidate(line).await {
            Some(r) => { info!("  → mdns resolved: {r}"); r }
            None => {
                info!("  → mdns resolve FAILED, dropping candidate");
                return None;
            }
        }
    } else {
        line.to_string()
    };
    match Candidate::from_sdp_string(&resolved) {
        Ok(c) => { info!("  → added to str0m"); Some(c) }
        Err(e) => { warn!("  → bad ice candidate: {e}"); None }
    }
}

// ---- hex + constant-time helpers ---------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode_fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
    if s.len() != N * 2 {
        bail!("hex string length {} != expected {}", s.len(), N * 2);
    }
    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk).map_err(|_| anyhow!("non-utf8 hex"))?;
        out[i] = u8::from_str_radix(byte_str, 16).map_err(|_| anyhow!("bad hex byte at {i}"))?;
    }
    Ok(out)
}

fn hex_decode_var(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("odd-length hex string");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("bad hex: {e}")))
        .collect()
}

fn constant_time_eq_bytes<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..N { diff |= a[i] ^ b[i]; }
    diff == 0
}
