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
pub async fn send_connect(server_url: &str, share_key: ShareKey, pre_generated_bulk_key: BulkKey) -> Result<LiveSession> {
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
        wire_version: Some(crate::WIRE_VERSION),
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
                    SignalFrame::PeerHello { wire_version, .. } if !peer_hello_seen => {
                        // Refuse the session if the peer speaks a different
                        // wire protocol version — the alternative is a
                        // silent mid-transfer decode failure that reads as
                        // "corrupted file." Better to bail cleanly here
                        // with an "update your client" message.
                        match wire_version {
                            Some(v) if v == crate::WIRE_VERSION => { /* ok */ }
                            Some(v) => bail!(
                                "peer speaks wire version {v}, we speak {}. Update the older client.",
                                crate::WIRE_VERSION
                            ),
                            None => bail!(
                                "peer did not advertise a wire version — it's running a pre-v{} client. Update the peer's bitmule.",
                                crate::WIRE_VERSION
                            ),
                        }
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

        // Sender-side: as soon as wrap_key is derived, wrap the pre-generated
        // bulk key and send KeyWrap over WS. Receiver decrypts + stores B.
        // B is generated by the caller (cmd_send) BEFORE the URL is printed so
        // that ShareLink.signature = SHA256(data || B) can be committed in the
        // URL fragment — see docs/crypto.md and crates/bitmule/src/main.rs.
        if wrap_key.is_some() && !key_wrap_sent {
            let b = pre_generated_bulk_key.clone();
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
        wire_version: Some(crate::WIRE_VERSION),
    }).await?;
    ws_send(&mut ws, &SignalFrame::PeerHello { receiver_id: Some(receiver_id), role: None, wire_version: Some(crate::WIRE_VERSION) }).await?;

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
                    SignalFrame::PeerHello { wire_version, .. } => {
                        // Server-injected peer_hello carrying the sender's
                        // wire_version. Bail on mismatch — the alternative
                        // is a silent decode failure mid-transfer.
                        match wire_version {
                            Some(v) if v == crate::WIRE_VERSION => { /* ok */ }
                            Some(v) => bail!(
                                "peer speaks wire version {v}, we speak {}. Update the older client.",
                                crate::WIRE_VERSION
                            ),
                            None => bail!(
                                "peer did not advertise a wire version — running a pre-v{} client. Update the peer's bitmule.",
                                crate::WIRE_VERSION
                            ),
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

    let meta_plain = serde_json::json!({
        "type": "meta",
        "name": name,
        "size": size,
        "chunkBytes": CHUNK_BYTES,
        "totalChunks": total_chunks,
    }).to_string();

    // Encrypt meta under meta_key with session_id as AAD (binds this meta to
    // this session). Wire framing: {"type":"meta_enc","nonce_hex":"..","ct_hex":".."}.
    let session_id_bytes: [u8; 32] = hex_decode_fixed(&session.session_id.as_hex())?;
    let (meta_nonce, meta_ct) = session.meta_key.encrypt_meta(&session_id_bytes, meta_plain.as_bytes())?;
    let meta_enc_frame = serde_json::json!({
        "type": "meta_enc",
        "nonce_hex": hex_encode(&meta_nonce),
        "ct_hex": hex_encode(&meta_ct),
    }).to_string();

    let bulk_key = session.bulk_key.as_ref()
        .ok_or_else(|| anyhow!("bulk_key missing at chunk-encrypt time — KEX handshake incomplete"))?
        .clone();

    // Set the flow-control threshold once, then send the encrypted meta as a text frame.
    channel_set_low_threshold(&mut session.rtc, session.channel_id, BUFFERED_LOW_THRESHOLD)?;
    channel_write_all(session, false, meta_enc_frame.as_bytes()).await?;

    let mut f = tokio::fs::File::open(file_path).await
        .with_context(|| format!("open {}", file_path.display()))?;
    let mut sent: u64 = 0;
    let mut buf = vec![0u8; CHUNK_BYTES];
    let mut idx: u64 = 0;
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 { break; }
        // AEAD-encrypt this chunk under bulk_key with a deterministic
        // nonce derived from idx. Receiver tracks its own idx counter so
        // the nonce doesn't need to ride on the wire.
        let ct = bulk_key.encrypt_chunk(idx, &buf[..n])?;
        channel_write_all(session, true, &ct).await?;
        sent += n as u64;
        idx += 1;
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
    let mut recv_idx: u64 = 0;
    let session_id_bytes: [u8; 32] = hex_decode_fixed(&session.session_id.as_hex())?;
    let bulk_key = session.bulk_key.as_ref()
        .ok_or_else(|| anyhow!("bulk_key missing at chunk-decrypt time — KEX handshake incomplete"))?
        .clone();

    let mut next_timeout = drain_rtc_capture_data(
        &mut session.rtc, &session.pool, session.channel_id,
        &mut meta_opt, &mut file_opt, &mut path_opt, &mut received, &mut done, &mut on_progress, out_dir,
        &bulk_key, &session.meta_key, &session_id_bytes, &mut recv_idx,
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
                            &bulk_key, &session.meta_key, &session_id_bytes, &mut recv_idx,
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
                    &bulk_key, &session.meta_key, &session_id_bytes, &mut recv_idx,
                ).await?;
            }

            _ = tokio::time::sleep(dur) => {
                session.rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("handle_input timeout: {e}"))?;
                next_timeout = drain_rtc_capture_data(
                    &mut session.rtc, &session.pool, session.channel_id,
                    &mut meta_opt, &mut file_opt, &mut path_opt, &mut received, &mut done, &mut on_progress, out_dir,
                    &bulk_key, &session.meta_key, &session_id_bytes, &mut recv_idx,
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
    bulk_key: &BulkKey,
    meta_key: &MetaKey,
    session_id_bytes: &[u8; 32],
    recv_idx: &mut u64,
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
                        // Decrypt this chunk with idx-derived nonce. SCTP is
                        // ordered so incrementing recv_idx per binary frame
                        // matches the sender's send-side idx exactly.
                        let plain = bulk_key.decrypt_chunk(*recv_idx, &data)
                            .with_context(|| format!("decrypt_chunk idx={}", *recv_idx))?;
                        f.write_all(&plain).await.context("write chunk")?;
                        *received += plain.len() as u64;
                        *recv_idx += 1;
                        if let Some(m) = meta_opt.as_ref() {
                            on_progress(*received, m.size, &m.name);
                        }
                    } else {
                        warn!("binary chunk arrived before meta — dropping {} bytes", data.len());
                    }
                } else {
                    // Text control frame: meta_enc or done.
                    let text = match std::str::from_utf8(&data) {
                        Ok(s) => s,
                        Err(_) => { warn!("non-utf8 text frame"); continue; }
                    };
                    let val: serde_json::Value = match serde_json::from_str(text) {
                        Ok(v) => v,
                        Err(_) => { warn!("bad text frame: {text}"); continue; }
                    };
                    match val.get("type").and_then(|x| x.as_str()) {
                        Some("meta_enc") => {
                            // Decrypt with meta_key, then parse inner MetaFrame.
                            let nonce_hex = val.get("nonce_hex").and_then(|x| x.as_str()).unwrap_or("");
                            let ct_hex = val.get("ct_hex").and_then(|x| x.as_str()).unwrap_or("");
                            let nonce = match hex_decode_var(nonce_hex) {
                                Ok(n) => n,
                                Err(e) => { warn!("meta_enc nonce hex: {e}"); continue }
                            };
                            let ct = match hex_decode_var(ct_hex) {
                                Ok(c) => c,
                                Err(e) => { warn!("meta_enc ct hex: {e}"); continue }
                            };
                            let plain = match meta_key.decrypt_meta(session_id_bytes, &nonce, &ct) {
                                Ok(p) => p,
                                Err(e) => { warn!("meta_enc decrypt: {e}"); continue }
                            };
                            match serde_json::from_slice::<MetaFrame>(&plain) {
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
                                Err(e) => warn!("meta decode after decrypt: {e}"),
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
    bulk_key: BulkKey,
    file_path: &Path,
    mode: TransportMode,
    on_progress: impl FnMut(u64, u64) + Send,
) -> Result<()> {
    match mode {
        TransportMode::Webrtc => send_file_webrtc(server_url_http, share_key, bulk_key, file_path, on_progress).await,
        TransportMode::Relay => send_file_relay(server_url_http, share_key, bulk_key, file_path, on_progress).await,
        TransportMode::Auto => {
            let dur = std::time::Duration::from_millis(WEBRTC_FALLBACK_MS);
            let progress = std::sync::Arc::new(tokio::sync::Mutex::new(on_progress));
            let webrtc_progress = progress.clone();
            let webrtc_bulk = bulk_key.clone();
            let webrtc_fut = async {
                let mut sess = tokio::time::timeout(dur, send_connect(server_url_http, share_key.clone(), webrtc_bulk)).await
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
                    send_file_relay(server_url_http, share_key, bulk_key, file_path, move |a, b| {
                        if let Ok(mut g) = relay_progress.try_lock() { g(a, b); }
                    }).await
                }
            }
        }
    }
}

/// Receive one file for `session_id`. Same dispatch shape as [`send_file`].
///
/// `expected_signature` — when `Some`, the on-disk file is stream-hashed
/// with the negotiated bulk key after the transfer completes and compared
/// (constant-time) against `SHA256(data || bulk_key)`. Mismatch = the URL
/// commitment doesn't hold, so the file gets deleted and an error is
/// returned. `None` skips the check (used by receiver-initiated flows
/// where the sender picks the file after the URL is minted).
pub async fn recv_file(
    server_url_http: &str,
    share_key: ShareKey,
    expected_signature: Option<[u8; 32]>,
    out_dir: &Path,
    mode: TransportMode,
    on_progress: impl FnMut(u64, u64, &str) + Send,
) -> Result<PathBuf> {
    // For DC + relay dispatch we need to hang on to the LiveSession's
    // bulk_key to run post-transfer verification. The relay path builds its
    // own transient session (crate::send_file_over_relay owns the crypto),
    // so signature verification on the relay path is a follow-up — for now
    // only the WebRTC path verifies.
    match mode {
        TransportMode::Webrtc => {
            let mut sess = recv_connect(server_url_http, share_key).await?;
            let path = recv_file_over_dc(&mut sess, out_dir, on_progress).await?;
            if let Some(sig) = expected_signature {
                verify_transferred_signature(&path, &sig, sess.bulk_key.as_ref()
                    .ok_or_else(|| anyhow!("session has no bulk key at verify time"))?).await?;
            }
            Ok(path)
        }
        TransportMode::Relay => recv_file_relay(server_url_http, share_key, expected_signature, out_dir, on_progress).await,
        TransportMode::Auto => {
            let dur = std::time::Duration::from_millis(WEBRTC_FALLBACK_MS);
            let progress = std::sync::Arc::new(tokio::sync::Mutex::new(on_progress));
            let webrtc_progress = progress.clone();
            let webrtc_fut = async {
                let mut sess = tokio::time::timeout(dur, recv_connect(server_url_http, share_key.clone())).await
                    .map_err(|_| anyhow!("webrtc DC open exceeded {} ms", WEBRTC_FALLBACK_MS))??;
                let path = recv_file_over_dc(&mut sess, out_dir, |a, b, n| {
                    if let Ok(mut g) = webrtc_progress.try_lock() { g(a, b, n); }
                }).await?;
                if let Some(sig) = expected_signature {
                    verify_transferred_signature(&path, &sig, sess.bulk_key.as_ref()
                        .ok_or_else(|| anyhow!("session has no bulk key at verify time"))?).await?;
                }
                Ok::<_, anyhow::Error>(path)
            };
            match webrtc_fut.await {
                Ok(p) => Ok(p),
                Err(e) => {
                    warn!("webrtc path failed ({e}), falling back to relay");
                    let relay_progress = progress.clone();
                    recv_file_relay(server_url_http, share_key, expected_signature, out_dir, move |a, b, n| {
                        if let Ok(mut g) = relay_progress.try_lock() { g(a, b, n); }
                    }).await
                }
            }
        }
    }
}

/// Stream `path` through SHA256 and fold in `bulk_key`, compare against
/// `expected` constant-time. Deletes `path` on mismatch and returns Err.
async fn verify_transferred_signature(
    path: &Path,
    expected: &[u8; 32],
    bulk_key: &BulkKey,
) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await
        .with_context(|| format!("open {} for signature verify", path.display()))?;
    let mut hasher = crate::crypto::CommitmentHasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    let computed = hasher.finalize(bulk_key);
    // Constant-time compare
    let mut diff: u8 = 0;
    for i in 0..32 { diff |= computed[i] ^ expected[i]; }
    if diff != 0 {
        let _ = tokio::fs::remove_file(path).await;
        bail!("URL signature mismatch — server or intermediate substituted the file; discarded");
    }
    Ok(())
}

// One-shot helpers per transport — avoid repeating the wire-up.

async fn send_file_webrtc(
    server_url_http: &str,
    share_key: ShareKey,
    bulk_key: BulkKey,
    file_path: &Path,
    on_progress: impl FnMut(u64, u64) + Send,
) -> Result<()> {
    let mut sess = send_connect(server_url_http, share_key, bulk_key).await?;
    send_file_over_dc(&mut sess, file_path, on_progress).await
}

async fn send_file_relay(
    server_url_http: &str,
    share_key: ShareKey,
    bulk_key: BulkKey,
    file_path: &Path,
    on_progress: impl FnMut(u64, u64) + Send,
) -> Result<()> {
    let session_hex = share_key.session_id_hex();
    let session_id = SessionId::from_hex(&session_hex)
        .map_err(|e| anyhow!("session_id from hex: {e}"))?;
    let mut ws = crate::open_ws(server_url_http, &session_hex).await?;
    // Sync bulk_key with receiver via KEX+KeyWrap over the same WS, BEFORE
    // dropping into the relay pump. The returned bulk_key is our own
    // pre-generated one — kept for future chunk encryption (Push B2).
    let session_id_bytes: [u8; 32] = hex_decode_fixed(&session_hex)?;
    let (bulk, meta) = handshake_bulk_key_over_ws(
        &mut ws, Role::Sender, &share_key, &session_id_bytes, Some(bulk_key),
    ).await?;
    let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let (in_tx, _in_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let progress = std::sync::Arc::new(tokio::sync::Mutex::new(crate::RelaySendProgress::default()));
    let _pump = tokio::spawn(pump_relay_ws(ws, out_rx, in_tx));
    crate::send_file_over_relay(
        server_url_http, &session_id, file_path, out_tx, progress,
        &bulk, &meta, &session_id_bytes,
        on_progress,
    ).await
}

async fn recv_file_relay(
    server_url_http: &str,
    share_key: ShareKey,
    expected_signature: Option<[u8; 32]>,
    out_dir: &Path,
    on_progress: impl FnMut(u64, u64, &str) + Send,
) -> Result<PathBuf> {
    let session_hex = share_key.session_id_hex();
    let session_id = SessionId::from_hex(&session_hex)
        .map_err(|e| anyhow!("session_id from hex: {e}"))?;
    let mut ws = crate::open_ws(server_url_http, &session_hex).await?;
    // Run KEX+KeyWrap over the WS to receive the bulk_key from the sender.
    // Do this BEFORE the pump takes over the ws so KEX frames don't race
    // chunk_relay frames.
    let session_id_bytes: [u8; 32] = hex_decode_fixed(&session_hex)?;
    let (bulk_key, meta_key) = handshake_bulk_key_over_ws(
        &mut ws, Role::Receiver, &share_key, &session_id_bytes, None,
    ).await?;
    let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let _pump = tokio::spawn(pump_relay_ws(ws, out_rx, in_tx));
    let _ = out_tx; // relay recv only reads; sender kept alive so pumper's send half stays valid
    let path = crate::recv_file_over_relay(
        server_url_http, &session_id, out_dir, in_rx,
        &bulk_key, &meta_key, &session_id_bytes,
        on_progress,
    ).await?;
    if let Some(sig) = expected_signature {
        verify_transferred_signature(&path, &sig, &bulk_key).await?;
    }
    Ok(path)
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

/// Run the KEX + KeyWrap subset of the connect handshake directly on `ws`.
/// Used by the relay-only path (which doesn't set up WebRTC) so both sides
/// still end up with a shared `BulkKey` — receiver can then verify the URL
/// signature commitment against the assembled file post-transfer, and a
/// compromised relay server cannot substitute a different plaintext without
/// invalidating `SHA256(data || bulk_key)`.
///
/// Must be called BEFORE spawning any pump task on the same `ws` — this
/// helper drives the socket directly during handshake so KEX frames don't
/// race with chunk_relay frames.
///
/// - Sender: pass `sender_bulk = Some(pre_generated_bulk_key)`; the helper
///   wraps it under the derived wrap_key and sends `KeyWrap` over the WS.
/// - Receiver: pass `sender_bulk = None`; the helper waits for `KeyWrap`
///   and returns the unwrapped bulk key.
pub(crate) async fn handshake_bulk_key_over_ws(
    ws: &mut Ws,
    role: Role,
    share_key: &ShareKey,
    session_id_bytes: &[u8; 32],
    sender_bulk: Option<BulkKey>,
) -> Result<(BulkKey, MetaKey)> {
    use futures_util::{SinkExt, StreamExt};
    // Local ephemeral, MAC'd with share_key so the peer can authenticate us.
    let local_ephemeral = Ephemeral::generate();
    let local_pub = local_ephemeral.public_bytes();
    let local_mac = share_key.mac_ephemeral_pub(&local_pub);
    ws_send(ws, &SignalFrame::KexPub {
        pub_hex: hex_encode(&local_pub),
        mac_hex: hex_encode(&local_mac),
    }).await?;

    let mut ephemeral_holder = Some(local_ephemeral);
    let mut wrap_key: Option<WrapKey> = None;
    let mut meta_key_opt: Option<MetaKey> = None;
    let mut bulk_key: Option<BulkKey> = None;
    let mut key_wrap_sent = false;

    loop {
        // Sender is done as soon as KeyWrap is sent; receiver as soon as
        // KeyWrap is unwrapped.
        match role {
            Role::Sender if key_wrap_sent => {
                let mk = meta_key_opt.take()
                    .ok_or_else(|| anyhow!("meta_key not derived on sender path"))?;
                let bk = sender_bulk.ok_or_else(|| anyhow!("sender bulk key vanished after send"))?;
                return Ok((bk, mk));
            }
            Role::Receiver => {
                if let (Some(b), Some(mk)) = (bulk_key.take(), meta_key_opt.take()) {
                    return Ok((b, mk));
                }
            }
            _ => {}
        }

        let msg = ws.next().await;
        let frame = match parse_ws_frame(msg)? {
            Some(f) => f,
            None => continue,
        };
        match frame {
            SignalFrame::KexPub { pub_hex, mac_hex } => {
                if wrap_key.is_some() {
                    warn!("duplicate KexPub during relay handshake — ignoring");
                    continue;
                }
                let peer_pub = hex_decode_fixed::<32>(&pub_hex)?;
                let peer_mac = hex_decode_fixed::<32>(&mac_hex)?;
                let expected_mac = share_key.mac_ephemeral_pub(&peer_pub);
                if !constant_time_eq_bytes(&expected_mac, &peer_mac) {
                    bail!("relay-handshake KexPub MAC verify failed — peer does not know share key");
                }
                let eph = ephemeral_holder.take()
                    .ok_or_else(|| anyhow!("local ephemeral gone before peer KexPub arrived"))?;
                let s = eph.derive_shared_secret(&peer_pub)?;
                let wk = s.wrap_key(session_id_bytes);
                let mk = s.meta_key(session_id_bytes);
                if let Role::Sender = role {
                    let b = sender_bulk.as_ref()
                        .ok_or_else(|| anyhow!("sender called handshake without sender_bulk"))?;
                    let (nonce, ct) = wk.wrap_bulk_key(b)?;
                    ws_send(ws, &SignalFrame::KeyWrap {
                        enc_b_hex: hex_encode(&ct),
                        nonce_hex: hex_encode(&nonce),
                    }).await?;
                    key_wrap_sent = true;
                }
                wrap_key = Some(wk);
                meta_key_opt = Some(mk);
            }
            SignalFrame::KeyWrap { enc_b_hex, nonce_hex } => {
                let wk = wrap_key.as_ref()
                    .ok_or_else(|| anyhow!("KeyWrap arrived before KEX complete"))?;
                let nonce = hex_decode_var(&nonce_hex)?;
                let ct = hex_decode_var(&enc_b_hex)?;
                bulk_key = Some(wk.unwrap_bulk_key(&nonce, &ct)?);
            }
            _ => { /* ignore other signaling frames during handshake */ }
        }
    }
}

async fn ws_send(ws: &mut Ws, frame: &SignalFrame) -> Result<()> {
    let text = serde_json::to_string(frame).context("frame encode")?;
    ws.send(Message::Text(text.into())).await.context("ws send")?;
    Ok(())
}

/// Send a frame with an optional `to_receiver_id` routing tag injected at
/// the JSON top level. Server (Phase M1) forwards to only that receiver.
/// `None` = fan-to-all (backward-compat with the single-receiver stack).
#[allow(dead_code)]
async fn ws_send_targeted(
    ws: &mut Ws,
    frame: &SignalFrame,
    to_receiver_id: Option<&str>,
) -> Result<()> {
    let mut v = serde_json::to_value(frame).context("frame encode")?;
    if let (Some(rid), Some(obj)) = (to_receiver_id, v.as_object_mut()) {
        obj.insert("to_receiver_id".to_string(), serde_json::Value::String(rid.to_string()));
    }
    let text = serde_json::to_string(&v).context("frame reencode")?;
    ws.send(Message::Text(text.into())).await.context("ws send")?;
    Ok(())
}

/// Send a frame from a receiver, tagging it with `from_receiver_id` at the
/// JSON top level so the sender's per-peer dispatch can route it. Server
/// (Phase M1b) verifies the tag matches the receiver's registered id.
#[allow(dead_code)]
async fn ws_send_from(
    ws: &mut Ws,
    frame: &SignalFrame,
    from_receiver_id: &str,
) -> Result<()> {
    let mut v = serde_json::to_value(frame).context("frame encode")?;
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "from_receiver_id".to_string(),
            serde_json::Value::String(from_receiver_id.to_string()),
        );
    }
    let text = serde_json::to_string(&v).context("frame reencode")?;
    ws.send(Message::Text(text.into())).await.context("ws send")?;
    Ok(())
}

/// Same shape as `parse_ws_frame`, but ALSO extracts the top-level
/// `from_receiver_id` (if present) alongside the parsed SignalFrame. Used
/// by the sender's per-peer dispatch to route an incoming answer / ICE /
/// KexPub / KeyWrap to the right per-peer task.
#[allow(dead_code)]
fn parse_ws_frame_with_from_id(
    msg: Option<Result<Message, tokio_tungstenite::tungstenite::Error>>,
) -> Result<Option<(SignalFrame, Option<String>)>> {
    let text = match msg {
        Some(Ok(Message::Text(t))) => t.to_string(),
        Some(Ok(Message::Close(_))) | None => bail!("ws closed pre-channel-open"),
        Some(Err(e)) => bail!("ws recv: {e}"),
        _ => return Ok(None),
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Ok(None);
    };
    let from = v.get("from_receiver_id").and_then(|x| x.as_str()).map(|s| s.to_string());
    let frame: Option<SignalFrame> = serde_json::from_value(v).ok();
    Ok(frame.map(|f| (f, from)))
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
