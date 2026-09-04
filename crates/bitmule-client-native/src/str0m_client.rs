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
use tokio::{io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt}, net::UdpSocket, sync::broadcast};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::{MetaFrame, Role, SignalFrame, Ws};
use crate::crypto::{BulkKey, Ephemeral, MetaKey, ShareKey, WrapKey};

/// A single received UDP packet — its bytes, source, and (critically)
/// the SPECIFIC local socket address it was delivered to. str0m's ICE
/// agent tracks known local candidates by their bound address, so we
/// need per-interface accuracy on the destination field or it drops
/// the packet as "unknown interface" (observed 2026-09-02 on Seb's box).
///
/// `Clone` for the M2b-5 broadcast-fanout path: each subscribed per-peer
/// Rtc gets its own copy and runs `Rtc::accepts()` locally to drop or
/// consume. Cost is one Vec<u8> clone per peer per packet; bytes are
/// ≤4 KiB and N is few tens of peers, so fine — see docs/multipeer.md §5.
#[derive(Clone)]
pub struct PoolRecv {
    pub bytes: Vec<u8>,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

/// One UdpSocket per host-candidate interface, all bound to the SAME
/// port. Recv is fan-in via a shared broadcast channel — per-socket
/// recv-loop tasks forward every packet with the destination correctly
/// set to the bound address of the socket that received it. Send routes
/// by source IP: str0m's Transmit outputs carry `source: SocketAddr` and
/// we dispatch to the matching socket so the outbound src-address matches
/// the local candidate str0m thinks it's using.
///
/// M2b-5: fan-in is `tokio::sync::broadcast` (not mpsc) so multiple
/// per-peer Rtcs can each subscribe and run `Rtc::accepts()` locally.
/// Legacy single-consumer callers (`send_connect`, `recv_connect`) use
/// the pre-subscribed `recv_rx` via `SocketPool::recv()` — same shape
/// as before, with a Lagged-drop warning inserted since broadcast is
/// bounded (mpsc was unbounded).
pub struct SocketPool {
    sockets: HashMap<IpAddr, Arc<UdpSocket>>,
    /// Held so late subscribers via `subscribe()` still get a live channel;
    /// dropping this closes the broadcast for every receiver.
    recv_tx: broadcast::Sender<PoolRecv>,
    /// Pre-subscribed receiver for the legacy single-consumer `recv()` path.
    recv_rx: broadcast::Receiver<PoolRecv>,
    _recv_tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// Broadcast capacity for pool packets (packet count, not bytes).
/// 1024 gives generous headroom vs a slow subscriber blocking str0m's
/// send_addr timing; a Lagged consumer just skips forward + logs, and
/// str0m's DTLS/SCTP retransmit handles the missing packet.
const POOL_BROADCAST_CAP: usize = 1024;

impl SocketPool {
    /// Async recv on the pre-subscribed receiver — single-consumer callers
    /// use this (send_connect, recv_connect legacy path). Lagged errors
    /// log + continue; Closed returns None (same shape as the old mpsc).
    pub async fn recv(&mut self) -> Option<PoolRecv> {
        use broadcast::error::RecvError;
        loop {
            match self.recv_rx.recv().await {
                Ok(pr) => return Some(pr),
                Err(RecvError::Lagged(n)) => {
                    warn!("pool.recv lagged: dropped {n} packets (single-consumer)");
                    continue;
                }
                Err(RecvError::Closed) => return None,
            }
        }
    }

    /// Fresh subscriber for M2b-5 per-peer Rtcs. Each peer task gets its
    /// own `broadcast::Receiver<PoolRecv>` + runs `Rtc::accepts()` locally
    /// to drop or consume. See `docs/multipeer.md` §"Startup + peer lifecycle".
    #[allow(dead_code)]
    pub fn subscribe(&self) -> broadcast::Receiver<PoolRecv> {
        self.recv_tx.subscribe()
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

/// Build a SocketPool with one UdpSocket per host-candidate interface.
/// All sockets share the same port so ICE candidates all look consistent
/// to the remote peer. Per-socket recv-loop tasks fan into a shared mpsc
/// so a single dispatch task can `select!` on one stream.
///
/// M2b-4 split (2026-09-04): pool creation is now separate from Rtc
/// creation so multiple Rtcs can share one pool. See
/// `build_rtc_with_pool_candidates` for the per-Rtc partner and
/// `dispatch_pool_recv_to_rtcs` for the inbound-packet-to-Rtc routing.
///
/// Fixes the "Discarding STUN request on unknown interface: 0.0.0.0:port"
/// bug (Seb 2026-09-02): binding once on 0.0.0.0 made socket.local_addr()
/// return the unspecified address, which str0m's ICE agent didn't
/// recognize as any known local candidate → drops. Per-IP sockets give
/// each recv a specific, matchable destination.
async fn build_socket_pool() -> Result<SocketPool> {
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

    // Spawn one recv task per socket that forwards packets into the pool's
    // broadcast channel. M2b-5: broadcast (not mpsc) so per-peer Rtcs can
    // each subscribe. Pre-subscribe `recv_rx` here so the legacy
    // single-consumer path still works via `SocketPool::recv()` even before
    // any peer task calls `subscribe()`.
    let (recv_tx, recv_rx) = broadcast::channel::<PoolRecv>(POOL_BROADCAST_CAP);
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
                        // broadcast::send Errs only when there are NO
                        // receivers at all; recv_rx on the pool + any
                        // per-peer subscribers keep the channel live.
                        // If the count really hits zero, the pool has
                        // been abandoned — exit the recv task.
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
    Ok(SocketPool { sockets, recv_tx, recv_rx, _recv_tasks: recv_tasks })
}

/// Build a fresh Rtc seeded with host candidates from `pool.bound_addrs()`.
/// Multiple Rtcs can share one SocketPool this way — each gets the same
/// set of local candidates. `dispatch_pool_recv_to_rtcs` routes inbound
/// packets to the owning Rtc via `Rtc::accepts()`.
pub(crate) fn build_rtc_with_pool_candidates(pool: &SocketPool) -> Rtc {
    let mut rtc = Rtc::new(Instant::now());
    for addr in pool.bound_addrs() {
        match Candidate::host(addr, "udp") {
            Ok(c) => { rtc.add_local_candidate(c); }
            Err(e) => warn!("skipping host candidate {addr}: {e}"),
        }
    }
    rtc
}

/// Legacy 1:1 helper — build a fresh SocketPool + one Rtc bound to it.
/// Kept for callers that don't need the shared-pool M2b-4 dispatch shape
/// (recv_connect, tests, exploratory code). New sender-side call sites
/// should use `build_socket_pool` + `build_rtc_with_pool_candidates`
/// directly and dispatch via `dispatch_pool_recv_to_rtcs`.
async fn build_rtc() -> Result<(Rtc, SocketPool)> {
    let pool = build_socket_pool().await?;
    let rtc = build_rtc_with_pool_candidates(&pool);
    Ok((rtc, pool))
}

/// Route one pool-recv packet to the first Rtc that accepts it. Returns
/// `Ok(Some(idx))` on match (caller must then drain that Rtc's
/// `poll_output`), `Ok(None)` if no Rtc claimed it (stray packet or peer
/// tore its Rtc down mid-flight — caller should log + drop, never
/// force-feed an unowned packet into a wrong Rtc), or `Err` if the
/// accepting Rtc's `handle_input` failed.
///
/// Correctness: `Rtc::accepts(&Input)` is str0m's authoritative
/// ownership check — it inspects ICE ufrag on STUN messages and matches
/// against the nominated send_addr on DTLS/RTP/RTCP traffic. Iterating
/// in accept-check order and stopping on the first match preserves that
/// authority; there is no fallback "guess the Rtc" path.
pub(crate) fn dispatch_pool_recv_to_rtcs(
    pr: &PoolRecv,
    rtcs: &mut [&mut Rtc],
) -> Result<Option<usize>> {
    let input = Input::Receive(Instant::now(), Receive {
        proto: Protocol::Udp,
        source: pr.source,
        destination: pr.destination,
        contents: pr.bytes.as_slice().try_into().map_err(|_| anyhow!("packet oversize"))?,
    });
    for (idx, rtc) in rtcs.iter_mut().enumerate() {
        if rtc.accepts(&input) {
            rtc.handle_input(input).map_err(|e| anyhow!("handle_input dispatch (rtc idx {idx}): {e}"))?;
            return Ok(Some(idx));
        }
    }
    Ok(None)
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

    let ws = crate::open_ws(&websocket_url(server_url)?, &session_hex).await?;
    // M2b-4: build the SocketPool once, then the sender-side Rtc against it.
    // Structure holds today for N=1 (this Rtc) and extends to N=peers in
    // M2b-5 with no dispatch-path changes — see dispatch_pool_recv_to_rtcs.
    let mut pool = build_socket_pool().await?;
    let mut rtc = build_rtc_with_pool_candidates(&pool);

    // M2b-3: hand the WS to a router+writer pair for the handshake. Router
    // dispatches inbound frames (unrouted here since no peer tasks yet);
    // writer serializes an outbox mpsc onto the sink. On DC-open we shut
    // both tasks down + reunite the sink+stream back into a `Ws` for
    // LiveSession so downstream file-transfer code stays unchanged.
    let (sink, stream) = ws.split();
    let crate::multipeer::WsWriterHandle {
        outbox_tx,
        task: writer_task,
    } = crate::multipeer::spawn_ws_writer(sink);
    let crate::multipeer::WsRouterHandle {
        register_tx: _,
        mut unrouted_rx,
        shutdown_tx: router_shutdown_tx,
        task: router_task,
    } = crate::multipeer::spawn_ws_router(stream);

    // Active side: create the data channel BEFORE offer generation so its
    // m-line lands in the SDP.
    let mut change = rtc.sdp_api();
    let channel_id = change.add_channel("bitmule".into());
    let (offer, pending) = change
        .apply()
        .ok_or_else(|| anyhow!("sdp_api produced no offer — nothing added"))?;
    let mut next_timeout = drain_rtc(&mut rtc, &pool).await?;

    crate::multipeer::ws_enqueue_targeted(&outbox_tx, &SignalFrame::Hello {
        role: Role::Sender.as_str().to_owned(),
        receiver_id: None,
        wire_version: Some(crate::WIRE_VERSION),
    }, None)?;

    // Crypto handshake — send our ephemeral immediately, wait for peer's
    // in the loop below (concurrent with SDP exchange).
    let local_ephemeral = Ephemeral::generate();
    let local_pub = local_ephemeral.public_bytes();
    let local_mac = share_key.mac_ephemeral_pub(&local_pub);
    crate::multipeer::ws_enqueue_targeted(&outbox_tx, &SignalFrame::KexPub {
        pub_hex: hex_encode(&local_pub),
        mac_hex: hex_encode(&local_mac),
    }, None)?;
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

    while !opened {
        let dur = (next_timeout - Instant::now()).max(std::time::Duration::from_millis(1));

        tokio::select! {
            maybe_frame = unrouted_rx.recv() => {
                // FIXME(m2b-3): router-error surfacing is weaker here than the
                // pre-M2b-3 shape. Before the split, `parse_ws_frame(maybe_msg)?`
                // propagated parse errors mid-handshake. Now a parse-Err inside
                // the router only shows up when we await `router_task` after
                // shutdown, so a mid-handshake parse-fail results in `recv()`
                // returning None → the `bail!` below fires with a generic
                // "router terminated" message instead of the underlying parse
                // error. Not blocking for M2b-3 (parse errors during ICE/SDP/KEX
                // are rare) but fix when the router lives past send_connect in
                // M2b-4 — probably a `health_rx: oneshot<Result<()>>` on the
                // handle that select! can watch alongside `unrouted_rx`.
                let frame = match maybe_frame {
                    Some(f) => f,
                    None => bail!("ws router terminated before DC opened"),
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
                        crate::multipeer::ws_enqueue_targeted(&outbox_tx, &SignalFrame::Sdp {
                            kind: "offer".into(),
                            sdp: offer_sdp,
                        }, None)?;
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
                // M2b-4: route through the N-Rtc dispatch helper (N=1 here).
                // `None` = no Rtc claimed the packet; log at debug + drop,
                // never force-feed an unowned packet into a wrong Rtc.
                let mut rtcs: [&mut Rtc; 1] = [&mut rtc];
                match dispatch_pool_recv_to_rtcs(&pr, &mut rtcs)? {
                    Some(_idx) => {
                        next_timeout = drain_rtc_capture_open(&mut rtc, &pool, channel_id, &mut opened).await?;
                    }
                    None => {
                        debug!("stray packet from {} on {} — no Rtc accepted, dropped", pr.source, pr.destination);
                    }
                }
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
            crate::multipeer::ws_enqueue_targeted(&outbox_tx, &SignalFrame::KeyWrap {
                enc_b_hex: hex_encode(&ct),
                nonce_hex: hex_encode(&nonce),
            }, None)?;
            bulk_key = Some(b);
            key_wrap_sent = true;
            info!("bulk key generated + wrapped + sent");
        }
    }
    info!("sender data channel open");
    let wrap_key = wrap_key.ok_or_else(|| anyhow!("DC opened before KEX completed"))?;
    let meta_key = meta_key.ok_or_else(|| anyhow!("DC opened before KEX completed"))?;
    let bulk_key = bulk_key.ok_or_else(|| anyhow!("DC opened before bulk key was generated"))?;

    // Tear down router+writer + reunite the WS. Drop-order matters: dropping
    // `outbox_tx` (the sole remaining sender clone in M2b-3, since no peer
    // tasks were spawned) closes the writer's mpsc → writer returns the sink.
    // Router shutdown_tx signal breaks the router's select! → router returns
    // the stream. Reunite yields the original Ws for LiveSession.
    let _ = router_shutdown_tx.send(true);
    drop(outbox_tx);
    let sink = writer_task.await.map_err(|e| anyhow!("ws writer join: {e}"))??;
    let stream = router_task.await.map_err(|e| anyhow!("ws router join: {e}"))??;
    let ws = stream.reunite(sink).map_err(|e| anyhow!("ws reunite: {e}"))?;

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
    let mut recv_idx: u64 = 0;
    let mut resume_from_chunk: Option<u64> = None;
    // M2b-7: request_ranges / recv_done state.
    //
    // On first tick after meta arrives, emit `RequestRanges` for the
    // (possibly resumed) missing chunk range. On the tick where
    // `recv_idx == total_chunks`, emit `RecvDone`. Both are one-shots.
    //
    // Wire compat: legacy single-peer sender ignores RequestRanges and
    // just streams. Legacy sender's `{"type":"done"}` and multipeer
    // sender's `{"type":"done_ack"}` are both treated as the end signal
    // by `drain_rtc_capture_data`.
    let mut request_sent = false;
    let mut recv_done_sent = false;
    let session_id_bytes: [u8; 32] = hex_decode_fixed(&session.session_id.as_hex())?;
    let bulk_key = session.bulk_key.as_ref()
        .ok_or_else(|| anyhow!("bulk_key missing at chunk-decrypt time — KEX handshake incomplete"))?
        .clone();

    let mut next_timeout = drain_rtc_capture_data(
        &mut session.rtc, &session.pool, session.channel_id,
        &mut meta_opt, &mut file_opt, &mut path_opt, &mut received, &mut done, &mut on_progress, out_dir,
        &bulk_key, &session.meta_key, &session_id_bytes, &mut recv_idx, &mut resume_from_chunk,
    ).await?;

    while !done {
        // M2b-7: one-shot RequestRanges emission after meta parsed.
        // total_chunks derived from meta.size so we ask for exactly the
        // range we're missing given any resume prefix.
        if !request_sent {
            if let Some(m) = meta_opt.as_ref() {
                let total_chunks = if m.size == 0 { 0 } else { (m.size + CHUNK_BYTES as u64 - 1) / CHUNK_BYTES as u64 };
                let start = resume_from_chunk.unwrap_or(0);
                if start < total_chunks {
                    // Half-open [start, end) in u32 chunk-index space.
                    // Wire cap is u32; a 64 TiB file at 16 KiB/chunk =
                    // ~4.3B chunks — hits u32::MAX. Real files today are
                    // well under, so plain cast is safe; add a bounds
                    // guard if we ever ship >64 TiB.
                    let req = crate::multipeer::DcControlFrame::RequestRanges {
                        ranges: vec![crate::multipeer::ChunkRange {
                            start: start as u32,
                            end: total_chunks as u32,
                        }],
                    };
                    let bytes = serde_json::to_vec(&req)
                        .map_err(|e| anyhow!("encode request_ranges: {e}"))?;
                    channel_write_all(session, false, &bytes).await?;
                    info!("emitted request_ranges [{}..{})", start, total_chunks);
                }
                request_sent = true;
                // Already-complete resume: nothing to request, skip
                // straight to recv_done below.
            }
        }

        // M2b-7: one-shot RecvDone emission once we've decrypted every
        // chunk. Sender responds with DoneAck; `done` flips in drain.
        if request_sent && !recv_done_sent {
            if let Some(m) = meta_opt.as_ref() {
                let total_chunks = if m.size == 0 { 0 } else { (m.size + CHUNK_BYTES as u64 - 1) / CHUNK_BYTES as u64 };
                if recv_idx >= total_chunks {
                    let bytes = serde_json::to_vec(&crate::multipeer::DcControlFrame::RecvDone)
                        .map_err(|e| anyhow!("encode recv_done: {e}"))?;
                    channel_write_all(session, false, &bytes).await?;
                    recv_done_sent = true;
                    info!("emitted recv_done (chunks {} / {})", recv_idx, total_chunks);
                }
            }
        }

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
                            &bulk_key, &session.meta_key, &session_id_bytes, &mut recv_idx, &mut resume_from_chunk,
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
                    &bulk_key, &session.meta_key, &session_id_bytes, &mut recv_idx, &mut resume_from_chunk,
                ).await?;
            }

            _ = tokio::time::sleep(dur) => {
                session.rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("handle_input timeout: {e}"))?;
                next_timeout = drain_rtc_capture_data(
                    &mut session.rtc, &session.pool, session.channel_id,
                    &mut meta_opt, &mut file_opt, &mut path_opt, &mut received, &mut done, &mut on_progress, out_dir,
                    &bulk_key, &session.meta_key, &session_id_bytes, &mut recv_idx, &mut resume_from_chunk,
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
    resume_from_chunk: &mut Option<u64>,
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
                                    // M2b-7: resume-aware open. If the file already exists
                                    // at `path` and is < declared size, treat its aligned
                                    // prefix as bytes we already have and request only the
                                    // missing ranges from the sender. Aligned = truncate down
                                    // to a chunk boundary so a mid-chunk crash re-transmits
                                    // the partial chunk cleanly.
                                    //
                                    // Correctness assumption: same URL = same bulk_key = same
                                    // plaintext, so any existing bytes at this path were
                                    // written by a prior receiver session for THE SAME file.
                                    // If the user pointed a different URL at the same out_dir
                                    // + name, the decrypted output will be garbage; that's
                                    // a --out-dir-hygiene concern, not something the wire
                                    // can detect without a full-file MAC.
                                    let existing_size = match tokio::fs::metadata(&path).await {
                                        Ok(s) if s.is_file() => s.len(),
                                        _ => 0,
                                    };
                                    let (mut file, have_chunks) = if existing_size > 0 && existing_size <= m.size {
                                        let full = existing_size / CHUNK_BYTES as u64;
                                        let aligned = full * CHUNK_BYTES as u64;
                                        let mut f = tokio::fs::OpenOptions::new()
                                            .read(true).write(true).create(true).truncate(false)
                                            .open(&path).await
                                            .with_context(|| format!("open (resume) {}", path.display()))?;
                                        if aligned != existing_size {
                                            f.set_len(aligned).await
                                                .with_context(|| format!("truncate {} to chunk boundary {}", path.display(), aligned))?;
                                        }
                                        f.seek(std::io::SeekFrom::End(0)).await?;
                                        info!("resuming {} from chunk {} (aligned bytes {})", path.display(), full, aligned);
                                        (f, full)
                                    } else {
                                        if existing_size > m.size {
                                            warn!("existing {} is larger ({} bytes) than declared size ({}) — truncating", path.display(), existing_size, m.size);
                                        }
                                        let f = tokio::fs::File::create(&path).await
                                            .with_context(|| format!("create {}", path.display()))?;
                                        (f, 0u64)
                                    };
                                    // Progress accounting: bytes covered by the resume
                                    // prefix are already "received."
                                    let resumed_bytes = have_chunks * CHUNK_BYTES as u64;
                                    *received = resumed_bytes;
                                    *recv_idx = have_chunks;
                                    *resume_from_chunk = Some(have_chunks);
                                    on_progress(resumed_bytes, m.size, &m.name);
                                    let _ = &mut file;
                                    *file_opt = Some(file);
                                    *path_opt = Some(path);
                                    *meta_opt = Some(m);
                                }
                                Err(e) => warn!("meta decode after decrypt: {e}"),
                            }
                        }
                        // Sender EOF markers: legacy single-peer sender emits
                        // `{"type":"done"}`; M2b-6 multipeer sender emits
                        // `{"type":"done_ack"}` after receiver's RecvDone.
                        // Both mean "no more chunks coming — close cleanly."
                        Some("done") | Some("done_ack") => { *done = true; }
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

/// M2b-8: multipeer send entry — opens the shared-WS + shared-pool
/// orchestrator and serves `file_path` to every peer that connects
/// under URL `server_url_http`.
///
/// - `ServeMode::Complete`: returns `Ok(())` as soon as the first peer
///   completes its DoneAck exchange. Every other in-flight peer task
///   is cleanly signalled to shut down before this returns.
/// - `ServeMode::Multi`: never returns `Ok`. Runs until the underlying
///   WS closes (returned as Err) or the caller aborts the future.
///
/// Relay incompatibility: the multipeer stack requires WebRTC — the
/// per-peer serve loop lives inside WebRTC data channels and there's
/// no relay-equivalent right now. If relay-multi is needed, the option
/// (a) shape from docs/multipeer.md §"Open questions" (single-B-shared
/// KEX over relay) can land in a follow-up; not in M2b-8.
pub async fn send_file_multi(
    server_url_http: &str,
    share_key: ShareKey,
    bulk_key: BulkKey,
    file_path: PathBuf,
    mode: crate::multipeer::ServeMode,
) -> Result<()> {
    let mut orch = send_serve(server_url_http, share_key, bulk_key, file_path, mode).await?;
    orch.await_complete().await
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
    use futures_util::{StreamExt};
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
pub(crate) async fn ws_send_targeted(
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
pub(crate) fn parse_ws_frame_with_from_id(
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

// ---- M2b-5: per-peer task spawn + long-lived sender orchestrator --------
//
// Structure (see docs/multipeer.md §"Startup + peer lifecycle"):
//
//   send_serve
//     ├── build_socket_pool                 (shared across peers)
//     ├── open_ws + spawn_ws_router/writer  (single WS, N peer inboxes)
//     ├── send Hello{role: sender}
//     └── orchestrator loop task
//           on unrouted_rx PeerHello:
//             version check + dup check → spawn_peer_task
//
//   spawn_peer_task
//     ├── build_rtc_with_pool_candidates(&pool)  (per-peer Rtc)
//     ├── pool.subscribe()                       (broadcast fanout)
//     ├── register per-peer inbox with router
//     ├── watch::channel for shutdown
//     └── spawn peer_session_run
//
//   peer_session_run
//     handshake body (mirrors send_connect's tail):
//       select! on {inbox_rx, pool_rx (accepts+handle_input+drain), shutdown, timeout}
//       → KEX: send own KexPub, verify peer's KexPub, derive wrap_key+meta_key
//       → wrap shared bulk_key + send KeyWrap
//       → send SDP offer, accept peer's answer
//       → wait for DC open
//     M2b-5 END: park on shutdown_rx.changed() (block-serve loop is M2b-6)
//
// Deliberate non-goals for this slice:
//   - cmd_send does not call send_serve (that's M2b-8; --multi flag).
//   - Block-serve loop (RequestRanges → chunks) lives in M2b-6.
//   - Receiver-side stays untouched.

use crate::multipeer::{
    ws_enqueue_targeted, CoveredNote, DcControlFrame, PeerHandle, PeerRegistration, PeerSession,
    SenderOrchestrator, SenderShared, WsRouterHandle,
};
use bitmule_core::ReceiverId;
use std::collections::HashSet;
use tokio::sync::{mpsc, watch, Mutex};

/// Spawn a per-peer serving task on receipt of a peer_hello. Registers
/// the peer's inbox with the WS router, subscribes the peer to the
/// pool's broadcast fanout, and hands the constructed PeerSession to
/// `peer_session_run` on a fresh task.
///
/// Returns a `PeerHandle` that the orchestrator stores in its peers
/// map for progress reporting + shutdown signalling.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn spawn_peer_task(
    receiver_id: ReceiverId,
    shared: Arc<SenderShared>,
    pool: Arc<SocketPool>,
    outbox_tx: mpsc::UnboundedSender<Message>,
    router_register: &mpsc::UnboundedSender<PeerRegistration>,
    note_tx: mpsc::UnboundedSender<CoveredNote>,
) -> Result<PeerHandle> {
    let rid_hex = receiver_id.as_hex();

    // Per-peer Rtc against the shared pool. `add_channel` MUST happen
    // before the offer is generated (active side) so the DC's m-line
    // lands in the SDP.
    let mut rtc = build_rtc_with_pool_candidates(&pool);
    let mut change = rtc.sdp_api();
    let channel_id = change.add_channel("bitmule".into());
    let (offer, pending) = change
        .apply()
        .ok_or_else(|| anyhow!("peer {} sdp_api produced no offer", rid_hex))?;

    // Per-peer inbox mpsc for signaling frames routed by from_receiver_id.
    // Await the router's ack before proceeding so the dispatch map is
    // live before any Ice/KexPub for this peer can arrive on the WS —
    // closes the µs-scale race where a fast peer's first frame could
    // otherwise land on `unrouted_rx` and get dropped. `spawn_peer_task`
    // paying a two-µs oneshot roundtrip is a good trade.
    let (inbox_tx, inbox_rx) = mpsc::unbounded_channel::<SignalFrame>();
    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel::<()>();
    router_register
        .send(PeerRegistration { receiver_id: rid_hex.clone(), inbox_tx, ack: ack_tx })
        .map_err(|e| anyhow!("router register (peer {rid_hex}): {e}"))?;
    ack_rx.await.map_err(|_| anyhow!("router dropped ack for peer {rid_hex} — router task exited?"))?;

    // Per-peer pool subscription — this peer's Rtc will call
    // `Rtc::accepts()` on each broadcast packet locally.
    let pool_rx = pool.subscribe();

    // Per-peer shutdown signal. Parent flips shutdown_tx→true to stop
    // this peer without touching the others.
    let (shutdown_tx, shutdown_rx) = watch::channel::<bool>(false);
    let covered = Arc::new(Mutex::new(HashSet::<u64>::new()));

    let session = PeerSession {
        receiver_id,
        rtc,
        channel_id,
        wrap_key: None,
        meta_key: None,
        covered: covered.clone(),
        shared,
    };

    let shutdown_rx_task = shutdown_rx.clone();
    let outbox_task = outbox_tx.clone();
    let pool_task = pool.clone();
    // Clone receiver_id for the task's error-path note; the task also
    // sends the receiver_id via the RecvDone note on clean exit.
    let receiver_id_for_note = receiver_id;
    let note_tx_for_task = note_tx.clone();
    let task = tokio::spawn(async move {
        let result = peer_session_run(
            session,
            pool_task,
            offer,
            pending,
            inbox_rx,
            pool_rx,
            outbox_task,
            shutdown_rx_task,
            note_tx_for_task.clone(),
        )
        .await;
        // On abnormal exit, notify the orchestrator so `await_complete`
        // can log + keep other peers alive. Clean exits already sent
        // RecvDone from inside the block-serve loop; don't double-notify.
        if let Err(ref e) = result {
            let _ = note_tx_for_task.send(CoveredNote::TaskError {
                receiver_id: receiver_id_for_note,
                error: format!("{e:#}"),
            });
        }
        result
    });

    Ok(PeerHandle {
        receiver_id,
        covered,
        shutdown_rx,
        _shutdown_tx: shutdown_tx,
        task,
    })
}

/// Per-peer serving task body. Runs handshake (KEX + SDP + DC-open),
/// then parks on shutdown_rx.changed() until the orchestrator flips
/// the signal. M2b-6 replaces the park with the block-serve loop.
///
/// Mirrors the tail of `send_connect` but reads signaling frames from
/// the router-supplied `inbox_rx` (already filtered by
/// `from_receiver_id == self.receiver_id`) instead of the shared
/// unrouted stream, and writes via `outbox_tx` with
/// `to_receiver_id = Some(self.receiver_id)`. Runs `Rtc::accepts()` on
/// each broadcast packet locally to drop foreign traffic without ever
/// touching the wrong Rtc.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
async fn peer_session_run(
    mut session: PeerSession,
    pool: Arc<SocketPool>,
    offer: SdpOffer,
    pending: str0m::change::SdpPendingOffer,
    mut inbox_rx: mpsc::UnboundedReceiver<SignalFrame>,
    mut pool_rx: broadcast::Receiver<PoolRecv>,
    outbox_tx: mpsc::UnboundedSender<Message>,
    mut shutdown_rx: watch::Receiver<bool>,
    note_tx: mpsc::UnboundedSender<CoveredNote>,
) -> Result<()> {
    let rid_hex = session.receiver_id.as_hex();
    info!(peer = %rid_hex, "peer task starting handshake");

    // Kick str0m to drain any startup outputs (mainly Timeout).
    let mut next_timeout = drain_rtc(&mut session.rtc, &pool).await?;

    // KEX: send our ephemeral immediately, wait for peer's KexPub in
    // the loop below (concurrent with SDP exchange).
    let local_ephemeral = Ephemeral::generate();
    let local_pub = local_ephemeral.public_bytes();
    let local_mac = session.shared.share_key.mac_ephemeral_pub(&local_pub);
    ws_enqueue_targeted(
        &outbox_tx,
        &SignalFrame::KexPub {
            pub_hex: hex_encode(&local_pub),
            mac_hex: hex_encode(&local_mac),
        },
        Some(&rid_hex),
    )?;

    let mut ephemeral_holder = Some(local_ephemeral);
    let mut wrap_key: Option<WrapKey> = None;
    let mut meta_key: Option<MetaKey> = None;
    let mut key_wrap_sent = false;
    let mut offer_holder: Option<SdpOffer> = Some(offer);
    let mut pending_holder: Option<str0m::change::SdpPendingOffer> = Some(pending);
    let mut opened = false;
    let channel_id = session.channel_id;

    // Send offer immediately — sender-active side owns the offer, and
    // the multipeer protocol does NOT require an incoming peer_hello on
    // this channel to trigger it (the orchestrator already saw the
    // peer_hello and spawned us; the peer's next signalling event is
    // its KexPub + SDP answer routed via inbox_rx).
    {
        let offer = offer_holder.take().expect("offer set on entry");
        let offer_sdp = offer.to_sdp_string();
        debug!(peer = %rid_hex, "OFFER SDP:\n{}", offer_sdp);
        ws_enqueue_targeted(
            &outbox_tx,
            &SignalFrame::Sdp { kind: "offer".into(), sdp: offer_sdp },
            Some(&rid_hex),
        )?;
    }

    while !opened {
        // If shutdown fires before DC-open, bail cleanly without error —
        // orchestrator torn us down (or --complete satisfied by another peer).
        if *shutdown_rx.borrow() {
            info!(peer = %rid_hex, "shutdown before DC-open — exiting peer task");
            return Ok(());
        }
        let dur = (next_timeout - Instant::now()).max(std::time::Duration::from_millis(1));

        tokio::select! {
            maybe_frame = inbox_rx.recv() => {
                let frame = match maybe_frame {
                    Some(f) => f,
                    None => bail!("peer {rid_hex} inbox closed before DC-open"),
                };
                match frame {
                    SignalFrame::Ice { candidate: Some(c) } => {
                        if let Some(remote) = parse_ice_candidate(&c).await {
                            session.rtc.add_remote_candidate(remote);
                            next_timeout = drain_rtc_capture_open(&mut session.rtc, &pool, channel_id, &mut opened).await?;
                        }
                    }
                    SignalFrame::Sdp { kind, sdp } if kind == "answer" => {
                        debug!(peer = %rid_hex, "ANSWER SDP:\n{}", sdp);
                        let ans = SdpAnswer::from_sdp_string(&sdp)
                            .map_err(|e| anyhow!("peer {rid_hex} parse answer: {e}"))?;
                        let pending_taken = pending_holder.take()
                            .ok_or_else(|| anyhow!("peer {rid_hex} answer arrived twice"))?;
                        session.rtc.sdp_api().accept_answer(pending_taken, ans)
                            .map_err(|e| anyhow!("peer {rid_hex} accept_answer: {e}"))?;
                        next_timeout = drain_rtc_capture_open(&mut session.rtc, &pool, channel_id, &mut opened).await?;
                    }
                    SignalFrame::KexPub { pub_hex, mac_hex } => {
                        if wrap_key.is_some() {
                            warn!(peer = %rid_hex, "duplicate KexPub — ignoring");
                            continue;
                        }
                        let peer_pub = hex_decode_fixed::<32>(&pub_hex)?;
                        let peer_mac = hex_decode_fixed::<32>(&mac_hex)?;
                        let expected_mac = session.shared.share_key.mac_ephemeral_pub(&peer_pub);
                        if !constant_time_eq_bytes(&expected_mac, &peer_mac) {
                            bail!("peer {rid_hex} KexPub MAC verify failed — does not know share key");
                        }
                        let eph = ephemeral_holder.take()
                            .ok_or_else(|| anyhow!("peer {rid_hex} local ephemeral gone before KexPub arrived"))?;
                        let s = eph.derive_shared_secret(&peer_pub)?;
                        wrap_key = Some(s.wrap_key(&session.shared.session_id_bytes));
                        meta_key = Some(s.meta_key(&session.shared.session_id_bytes));
                        info!(peer = %rid_hex, "KEX complete");
                    }
                    _ => {
                        debug!(peer = %rid_hex, "peer task ignoring frame (pre-DC-open)");
                    }
                }
            }

            maybe_pr = pool_rx.recv() => {
                use broadcast::error::RecvError;
                let pr = match maybe_pr {
                    Ok(p) => p,
                    Err(RecvError::Lagged(n)) => {
                        warn!(peer = %rid_hex, "pool rx lagged {n} — str0m re-tx will handle");
                        continue;
                    }
                    Err(RecvError::Closed) => bail!("peer {rid_hex} pool rx closed"),
                };
                // Local accepts-check: broadcast fans EVERY packet to
                // EVERY peer; each peer's Rtc filters via `accepts()`.
                let mut rtcs: [&mut Rtc; 1] = [&mut session.rtc];
                match dispatch_pool_recv_to_rtcs(&pr, &mut rtcs)? {
                    Some(_idx) => {
                        next_timeout = drain_rtc_capture_open(&mut session.rtc, &pool, channel_id, &mut opened).await?;
                    }
                    None => {
                        // Foreign packet — belongs to another peer's Rtc.
                        // Silent drop is correct; another peer's task will
                        // accept it on its own broadcast subscription.
                    }
                }
            }

            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!(peer = %rid_hex, "shutdown signalled — exiting peer task");
                    return Ok(());
                }
            }

            _ = tokio::time::sleep(dur) => {
                session.rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("peer {rid_hex} handle_input timeout: {e}"))?;
                next_timeout = drain_rtc_capture_open(&mut session.rtc, &pool, channel_id, &mut opened).await?;
            }
        }

        // Once wrap_key is derived, wrap the shared bulk_key and send
        // KeyWrap. Bulk key is SAME B for every peer — URL commitment.
        if wrap_key.is_some() && !key_wrap_sent {
            let wk = wrap_key.as_ref().unwrap();
            let (nonce, ct) = wk.wrap_bulk_key(&session.shared.bulk_key)?;
            ws_enqueue_targeted(
                &outbox_tx,
                &SignalFrame::KeyWrap {
                    enc_b_hex: hex_encode(&ct),
                    nonce_hex: hex_encode(&nonce),
                },
                Some(&rid_hex),
            )?;
            key_wrap_sent = true;
            info!(peer = %rid_hex, "bulk key wrapped + sent");
        }
    }

    let wrap_key = wrap_key.ok_or_else(|| anyhow!("peer {rid_hex} DC opened before KEX completed"))?;
    let meta_key = meta_key.ok_or_else(|| anyhow!("peer {rid_hex} DC opened before KEX completed"))?;
    session.wrap_key = Some(wrap_key);
    session.meta_key = Some(meta_key);
    info!(peer = %rid_hex, "DC open — entering block-serve loop (M2b-6)");

    // M2b-6: block-serve loop.
    //
    // 1. Send meta_enc as the first text frame on DC (AEAD-wrap the file
    //    meta under the per-peer meta_key, session_id_bytes as AAD).
    // 2. Set flow-control threshold once.
    // 3. Loop:
    //     - Drain any queued incoming DC text frames (RequestRanges /
    //       RecvDone), serve chunks or ack + exit.
    //     - Select on {shutdown, pool_rx (drain + capture DC data),
    //       inbox_rx (Ice trickle), timeout}.
    //
    // Complete-mode cross-peer shutdown is NOT wired here — M2b-8 adds it
    // once cmd_send + --multi land. Complete mode today just serves this
    // peer through recv_done + DoneAck like Multi does.

    let meta_key_ref = session.meta_key.as_ref().expect("meta_key set above");
    let meta_enc_bytes = build_meta_enc_payload(
        &session.shared.session_id_bytes,
        meta_key_ref,
        &session.shared.file_path,
        session.shared.file_size,
        session.shared.total_chunks,
    )?;

    channel_set_low_threshold(&mut session.rtc, session.channel_id, BUFFERED_LOW_THRESHOLD)?;

    let mut dc_in: Vec<(bool, Vec<u8>)> = Vec::new();
    channel_write_all_peer(
        &mut session.rtc,
        &pool,
        session.channel_id,
        false,
        &meta_enc_bytes,
        &mut pool_rx,
        &mut dc_in,
    )
    .await?;
    info!(peer = %rid_hex, "meta_enc sent");

    let mut file = tokio::fs::File::open(&session.shared.file_path)
        .await
        .with_context(|| format!("open {}", session.shared.file_path.display()))?;

    let mut next_timeout =
        drain_rtc_capture_dc_frames(&mut session.rtc, &pool, session.channel_id, &mut dc_in).await?;

    let mut recv_done = false;
    while !recv_done {
        if *shutdown_rx.borrow() {
            info!(peer = %rid_hex, "shutdown mid-serve — exiting peer task");
            return Ok(());
        }

        // Process queued DC frames first (RequestRanges / RecvDone).
        // `dc_in` accumulates from the last drain; drain here so serve calls
        // during processing don't concurrently push into a Vec we're iterating.
        let batch: Vec<(bool, Vec<u8>)> = dc_in.drain(..).collect();
        for (binary, data) in batch {
            if binary {
                warn!(peer = %rid_hex, "receiver sent binary DC data ({} bytes) — protocol violation, ignoring", data.len());
                continue;
            }
            match serde_json::from_slice::<DcControlFrame>(&data) {
                Ok(DcControlFrame::RequestRanges { ranges }) => {
                    for r in ranges {
                        if r.end <= r.start {
                            warn!(peer = %rid_hex, "empty/inverted range {}..{} — skipping", r.start, r.end);
                            continue;
                        }
                        let total_u32: u32 = session.shared.total_chunks.min(u32::MAX as u64) as u32;
                        if r.start > total_u32 || r.end > total_u32 {
                            warn!(peer = %rid_hex, "range {}..{} out of bounds (total_chunks {}) — clamping", r.start, r.end, total_u32);
                        }
                        let start = r.start.min(total_u32);
                        let end = r.end.min(total_u32);
                        serve_range(
                            &mut file,
                            &session.shared,
                            start..end,
                            &session.covered,
                            &mut session.rtc,
                            &pool,
                            session.channel_id,
                            &mut pool_rx,
                            &mut dc_in,
                        )
                        .await?;
                    }
                    next_timeout = drain_rtc_capture_dc_frames(
                        &mut session.rtc, &pool, session.channel_id, &mut dc_in,
                    )
                    .await?;
                }
                Ok(DcControlFrame::RecvDone) => {
                    // Peer has assembled the whole file locally. Ack + exit.
                    let ack = serde_json::to_vec(&DcControlFrame::DoneAck)
                        .map_err(|e| anyhow!("encode DoneAck: {e}"))?;
                    channel_write_all_peer(
                        &mut session.rtc,
                        &pool,
                        session.channel_id,
                        false,
                        &ack,
                        &mut pool_rx,
                        &mut dc_in,
                    )
                    .await?;
                    drain_until_buffer_empty_peer(
                        &mut session.rtc,
                        &pool,
                        session.channel_id,
                        &mut pool_rx,
                        &mut dc_in,
                    )
                    .await?;
                    info!(peer = %rid_hex, "recv_done + DoneAck exchanged — exiting peer task");
                    // M2b-8: notify orchestrator this peer got the file
                    // so `await_complete` can fire the mode-aware exit
                    // (Complete: shut down siblings; Multi: keep serving).
                    let _ = note_tx.send(CoveredNote::RecvDone {
                        receiver_id: session.receiver_id,
                    });
                    recv_done = true;
                    break;
                }
                Ok(DcControlFrame::DoneAck) => {
                    warn!(peer = %rid_hex, "receiver sent DoneAck — wrong direction, ignoring");
                }
                Err(e) => {
                    warn!(peer = %rid_hex, "malformed DC control frame ({} bytes): {e}", data.len());
                }
            }
        }
        if recv_done { break; }

        let dur = (next_timeout - Instant::now()).max(std::time::Duration::from_millis(1));
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!(peer = %rid_hex, "shutdown signalled — exiting peer task");
                    return Ok(());
                }
            }
            maybe_frame = inbox_rx.recv() => {
                // Post-DC-open signaling: apply late ICE trickle, ignore rest.
                match maybe_frame {
                    Some(SignalFrame::Ice { candidate: Some(c) }) => {
                        if let Some(remote) = parse_ice_candidate(&c).await {
                            session.rtc.add_remote_candidate(remote);
                            next_timeout = drain_rtc_capture_dc_frames(
                                &mut session.rtc, &pool, session.channel_id, &mut dc_in,
                            )
                            .await?;
                        }
                    }
                    Some(_) => { /* stale signaling — ignore */ }
                    None => {
                        warn!(peer = %rid_hex, "inbox closed mid-serve — exiting");
                        return Ok(());
                    }
                }
            }
            maybe_pr = pool_rx.recv() => {
                use broadcast::error::RecvError;
                match maybe_pr {
                    Ok(pr) => {
                        let mut rtcs: [&mut Rtc; 1] = [&mut session.rtc];
                        if dispatch_pool_recv_to_rtcs(&pr, &mut rtcs)?.is_some() {
                            next_timeout = drain_rtc_capture_dc_frames(
                                &mut session.rtc, &pool, session.channel_id, &mut dc_in,
                            )
                            .await?;
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        warn!(peer = %rid_hex, "pool rx lagged {n} — str0m re-tx will handle");
                    }
                    Err(RecvError::Closed) => bail!("peer {rid_hex} pool rx closed"),
                }
            }
            _ = tokio::time::sleep(dur) => {
                session.rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("peer {rid_hex} handle_input timeout: {e}"))?;
                next_timeout = drain_rtc_capture_dc_frames(
                    &mut session.rtc, &pool, session.channel_id, &mut dc_in,
                )
                .await?;
            }
        }
    }

    info!(peer = %rid_hex, "peer task exit clean");
    Ok(())
}

/// Build the meta_enc DC payload — AEAD-wrap the file MetaFrame under
/// this peer's meta_key with session_id_bytes as AAD. Result is the
/// text bytes to write on the DC as the first frame.
///
/// M2b-6: mirrors the meta_enc build in `send_file_over_dc` so the
/// single-peer receiver code can decrypt without a wire change.
fn build_meta_enc_payload(
    session_id_bytes: &[u8; 32],
    meta_key: &MetaKey,
    file_path: &Path,
    file_size: u64,
    total_chunks: u64,
) -> Result<Vec<u8>> {
    let name = file_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".to_string());
    let meta_plain = serde_json::json!({
        "type": "meta",
        "name": name,
        "size": file_size,
        "chunkBytes": CHUNK_BYTES,
        "totalChunks": total_chunks,
    })
    .to_string();
    let (nonce, ct) = meta_key.encrypt_meta(session_id_bytes, meta_plain.as_bytes())?;
    let frame = serde_json::json!({
        "type": "meta_enc",
        "nonce_hex": hex_encode(&nonce),
        "ct_hex": hex_encode(&ct),
    })
    .to_string();
    Ok(frame.into_bytes())
}

/// Serve one contiguous chunk range: seek + one big read (Seb's
/// optimization from docs/multipeer.md §"Request-ranges wire") →
/// split into `CHUNK_BYTES` pieces → AEAD-encrypt each with
/// `bulk_key.encrypt_chunk(idx, plaintext)` → write binary on DC.
/// Records each idx in `covered` after successful DC write.
///
/// Range is half-open `[start, end)`; caller has already validated
/// bounds vs `total_chunks`.
#[allow(clippy::too_many_arguments)]
async fn serve_range(
    file: &mut tokio::fs::File,
    shared: &SenderShared,
    range: std::ops::Range<u32>,
    covered: &Arc<Mutex<HashSet<u64>>>,
    rtc: &mut Rtc,
    pool: &SocketPool,
    channel_id: ChannelId,
    pool_rx: &mut broadcast::Receiver<PoolRecv>,
    dc_in: &mut Vec<(bool, Vec<u8>)>,
) -> Result<()> {
    let n_chunks = (range.end - range.start) as u64;
    let start_offset = range.start as u64 * CHUNK_BYTES as u64;
    let want_bytes = (n_chunks * CHUNK_BYTES as u64).min(shared.file_size.saturating_sub(start_offset));
    if want_bytes == 0 {
        return Ok(());
    }
    file.seek(std::io::SeekFrom::Start(start_offset))
        .await
        .with_context(|| format!("seek to chunk {} (offset {})", range.start, start_offset))?;
    let mut buf = vec![0u8; want_bytes as usize];
    file.read_exact(&mut buf)
        .await
        .with_context(|| format!("read {} bytes from chunk {}", want_bytes, range.start))?;

    let mut written = 0usize;
    let mut idx = range.start as u64;
    while written < buf.len() {
        let end = (written + CHUNK_BYTES).min(buf.len());
        let ct = shared.bulk_key.encrypt_chunk(idx, &buf[written..end])?;
        channel_write_all_peer(rtc, pool, channel_id, true, &ct, pool_rx, dc_in).await?;
        {
            let mut c = covered.lock().await;
            c.insert(idx);
        }
        written = end;
        idx += 1;
    }
    Ok(())
}

/// Peer-task equivalent of `channel_write_all`: writes `buf` to the DC,
/// awaiting SCTP backpressure by pumping the pool_rx + timeout mini loop
/// until str0m fires `ChannelBufferedAmountLow` and the write is accepted.
/// Any DC data events observed during the backpressure pump land in
/// `dc_in` so the outer block-serve loop processes them on next iteration.
async fn channel_write_all_peer(
    rtc: &mut Rtc,
    pool: &SocketPool,
    channel_id: ChannelId,
    binary: bool,
    buf: &[u8],
    pool_rx: &mut broadcast::Receiver<PoolRecv>,
    dc_in: &mut Vec<(bool, Vec<u8>)>,
) -> Result<()> {
    let mut next_timeout = drain_rtc_capture_dc_frames(rtc, pool, channel_id, dc_in).await?;
    loop {
        let accepted = {
            let mut ch = rtc
                .channel(channel_id)
                .ok_or_else(|| anyhow!("channel {:?} gone", channel_id))?;
            ch.write(binary, buf).map_err(|e| anyhow!("channel write: {e}"))?
        };
        if accepted {
            next_timeout = drain_rtc_capture_dc_frames(rtc, pool, channel_id, dc_in).await?;
            let _ = next_timeout;
            return Ok(());
        }
        let dur = (next_timeout - Instant::now()).max(std::time::Duration::from_millis(1));
        tokio::select! {
            maybe_pr = pool_rx.recv() => {
                use broadcast::error::RecvError;
                match maybe_pr {
                    Ok(pr) => {
                        let mut rtcs: [&mut Rtc; 1] = [rtc];
                        if dispatch_pool_recv_to_rtcs(&pr, &mut rtcs)?.is_some() {
                            next_timeout = drain_rtc_capture_dc_frames(rtcs[0], pool, channel_id, dc_in).await?;
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        warn!("channel_write_all_peer pool lagged {n}");
                    }
                    Err(RecvError::Closed) => bail!("pool rx closed mid-write"),
                }
            }
            _ = tokio::time::sleep(dur) => {
                rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("handle_input timeout: {e}"))?;
                next_timeout = drain_rtc_capture_dc_frames(rtc, pool, channel_id, dc_in).await?;
            }
        }
    }
}

/// Drain str0m outputs, capturing ChannelData events for `expected_channel`
/// into `dc_in` as `(binary, bytes)` pairs. Other events go through
/// `handle_generic_event` (ICE state, transmit, etc). Returns the next
/// Timeout instant per str0m's drain-to-completion contract.
async fn drain_rtc_capture_dc_frames(
    rtc: &mut Rtc,
    pool: &SocketPool,
    expected_channel: ChannelId,
    dc_in: &mut Vec<(bool, Vec<u8>)>,
) -> Result<Instant> {
    loop {
        match rtc.poll_output().map_err(|e| anyhow!("poll_output: {e}"))? {
            Output::Timeout(t) => return Ok(t),
            Output::Transmit(t) => {
                pool.send_from(t.source, t.destination, &t.contents)
                    .await
                    .with_context(|| format!("send_to {}", t.destination))?;
            }
            Output::Event(Event::ChannelData(ChannelData { id, binary, data })) if id == expected_channel => {
                dc_in.push((binary, data));
            }
            Output::Event(e) => handle_generic_event(&e)?,
        }
    }
}

/// Peer-task equivalent of `drain_until_buffer_empty` — waits for SCTP to
/// flush any queued writes before returning. Called after DoneAck so the
/// task can exit without truncating the ack on the wire.
async fn drain_until_buffer_empty_peer(
    rtc: &mut Rtc,
    pool: &SocketPool,
    channel_id: ChannelId,
    pool_rx: &mut broadcast::Receiver<PoolRecv>,
    dc_in: &mut Vec<(bool, Vec<u8>)>,
) -> Result<()> {
    let mut next_timeout = drain_rtc_capture_dc_frames(rtc, pool, channel_id, dc_in).await?;
    loop {
        let buffered = {
            let mut ch = rtc
                .channel(channel_id)
                .ok_or_else(|| anyhow!("channel {:?} gone", channel_id))?;
            ch.buffered_amount()
        };
        if buffered == 0 {
            return Ok(());
        }
        let dur = (next_timeout - Instant::now()).max(std::time::Duration::from_millis(1));
        tokio::select! {
            maybe_pr = pool_rx.recv() => {
                use broadcast::error::RecvError;
                match maybe_pr {
                    Ok(pr) => {
                        let mut rtcs: [&mut Rtc; 1] = [rtc];
                        if dispatch_pool_recv_to_rtcs(&pr, &mut rtcs)?.is_some() {
                            next_timeout = drain_rtc_capture_dc_frames(rtcs[0], pool, channel_id, dc_in).await?;
                        }
                    }
                    Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => bail!("pool rx closed during drain"),
                }
            }
            _ = tokio::time::sleep(dur) => {
                rtc.handle_input(Input::Timeout(Instant::now()))
                    .map_err(|e| anyhow!("handle_input timeout: {e}"))?;
                next_timeout = drain_rtc_capture_dc_frames(rtc, pool, channel_id, dc_in).await?;
            }
        }
    }
}

/// Long-lived sender-side entry point for the multipeer path. Opens WS,
/// wires router+writer, sends Hello, then spawns the orchestrator loop
/// task that receives peer_hello notifications and spawns per-peer
/// serving tasks. Returns a `SenderOrchestrator` handle whose fields
/// hold the pool + router + writer + peers map alive for the run.
///
/// M2b-6: `file_path` + `mode` land in SenderShared so per-peer tasks can
/// send `meta_enc` on DC-open + serve chunk ranges. cmd_send still stays
/// on send_connect — the `--multi` wire-up + Complete-mode early-exit
/// predicate ride on M2b-8. Complete mode here does NOT yet shut down
/// sibling peers when one reaches full coverage; only the recv_done
/// exchange on this peer exits its own task.
#[allow(dead_code)]
pub async fn send_serve(
    server_url: &str,
    share_key: ShareKey,
    pre_generated_bulk_key: BulkKey,
    file_path: PathBuf,
    mode: crate::multipeer::ServeMode,
) -> Result<SenderOrchestrator> {
    let session_hex = share_key.session_id_hex();
    info!(session = %session_hex, "opening multipeer sender WS + shared pool");

    // Stat the file once at start — every peer task reads size + total_chunks
    // from SenderShared without a re-stat.
    let stat = tokio::fs::metadata(&file_path).await
        .with_context(|| format!("stat {}", file_path.display()))?;
    if !stat.is_file() {
        bail!("{} is not a regular file", file_path.display());
    }
    let file_size = stat.len();
    let total_chunks = if file_size == 0 { 0 } else { (file_size + CHUNK_BYTES as u64 - 1) / CHUNK_BYTES as u64 };

    let ws = crate::open_ws(&websocket_url(server_url)?, &session_hex).await?;
    let pool = Arc::new(build_socket_pool().await?);

    let (sink, stream) = ws.split();
    let writer = crate::multipeer::spawn_ws_writer(sink);
    let router = crate::multipeer::spawn_ws_router(stream);

    let session_id_bytes: [u8; 32] = hex_decode_fixed(&session_hex)?;
    let shared = Arc::new(SenderShared {
        share_key,
        bulk_key: pre_generated_bulk_key,
        session_id_bytes,
        wire_version: crate::WIRE_VERSION,
        file_path,
        file_size,
        total_chunks,
        mode,
    });

    // Sender-side Hello — no to_receiver_id (server broadcasts).
    ws_enqueue_targeted(
        &writer.outbox_tx,
        &SignalFrame::Hello {
            role: Role::Sender.as_str().to_owned(),
            receiver_id: None,
            wire_version: Some(shared.wire_version),
        },
        None,
    )?;

    let peers: Arc<Mutex<HashMap<String, PeerHandle>>> = Arc::new(Mutex::new(HashMap::new()));

    // M2b-8: peer-task → orchestrator note channel. Peer tasks send
    // RecvDone after a clean DoneAck exchange and TaskError on abnormal
    // exit. `SenderOrchestrator::await_complete` consumes this to drive
    // the mode-aware exit predicate.
    let (note_tx, note_rx) = mpsc::unbounded_channel::<CoveredNote>();

    // Orchestrator loop: consume unrouted frames (PeerHello notifications
    // from the signaling server). Spawn per-peer task on each new one;
    // ignore duplicates; bail on version mismatch as send_connect does.
    let peers_loop = peers.clone();
    let shared_loop = shared.clone();
    let outbox_loop = writer.outbox_tx.clone();
    let register_loop = router.register_tx.clone();
    let pool_loop = pool.clone();
    let note_tx_loop = note_tx.clone();
    // Move the unrouted receiver into the loop task; the WsRouterHandle
    // gave it to us by value in the handle struct.
    // NOTE: WsRouterHandle::unrouted_rx is owned by the handle; take it
    // via a small dance so the returned SenderOrchestrator still holds
    // the handle for its shutdown_tx + join.
    let WsRouterHandle {
        register_tx,
        mut unrouted_rx,
        shutdown_tx: router_shutdown_tx,
        task: router_task,
    } = router;
    let _ = register_loop; // register_tx used inside loop via `register_tx.clone()`
    let register_for_loop = register_tx.clone();
    let loop_task = tokio::spawn(async move {
        while let Some(frame) = unrouted_rx.recv().await {
            let (rid_hex_opt, wire_v) = match &frame {
                SignalFrame::PeerHello { receiver_id, wire_version, .. } => {
                    (receiver_id.clone(), *wire_version)
                }
                _ => {
                    debug!("orchestrator: dropping unexpected unrouted frame");
                    continue;
                }
            };
            let rid_hex = match rid_hex_opt {
                Some(r) => r,
                None => {
                    warn!("orchestrator: peer_hello without receiver_id — dropping");
                    continue;
                }
            };
            match wire_v {
                Some(v) if v == shared_loop.wire_version => { /* ok */ }
                Some(v) => {
                    warn!(
                        "peer {rid_hex} speaks wire version {v}, we speak {} — dropping peer",
                        shared_loop.wire_version
                    );
                    continue;
                }
                None => {
                    warn!("peer {rid_hex} did not advertise wire version — dropping peer");
                    continue;
                }
            }
            {
                let peers_g = peers_loop.lock().await;
                if peers_g.contains_key(&rid_hex) {
                    debug!("duplicate peer_hello for {rid_hex} — ignoring");
                    continue;
                }
            }
            let receiver_id = match ReceiverId::from_hex(&rid_hex) {
                Ok(r) => r,
                Err(e) => {
                    warn!("peer_hello receiver_id parse ({rid_hex}): {e} — dropping");
                    continue;
                }
            };
            match spawn_peer_task(
                receiver_id,
                shared_loop.clone(),
                pool_loop.clone(),
                outbox_loop.clone(),
                &register_for_loop,
                note_tx_loop.clone(),
            )
            .await
            {
                Ok(handle) => {
                    let mut peers_g = peers_loop.lock().await;
                    peers_g.insert(rid_hex, handle);
                }
                Err(e) => {
                    warn!("spawn_peer_task failed for {rid_hex}: {e}");
                }
            }
        }
        Ok(())
    });

    // Re-assemble the router handle for the SenderOrchestrator (peers
    // + loop own the register_tx clones + unrouted_rx moved-into-loop).
    let router = WsRouterHandle {
        register_tx,
        // unrouted_rx was moved into loop_task; replace with a dead one
        // so the handle still type-checks (shutdown path uses shutdown_tx).
        unrouted_rx: mpsc::unbounded_channel::<SignalFrame>().1,
        shutdown_tx: router_shutdown_tx,
        task: router_task,
    };

    // Drop the seed note_tx clone we minted at the top so
    // note_rx.recv() returns None once every peer-task tx clone
    // exits (belt-and-braces: `await_complete` treats that None as
    // "orchestrator dead, propagate Err" — fine because it should
    // never occur under normal Complete/Multi lifecycles).
    drop(note_tx);

    Ok(SenderOrchestrator {
        shared,
        peers,
        router,
        writer,
        loop_task,
        note_rx,
    })
}
