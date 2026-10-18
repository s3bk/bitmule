//! Sender -> server -> receiver: the handshake over the signaling channel,
//! the data over the relay (fountain coded) or over a WebRTC data channel.

use std::sync::Arc;

use bitmule::v2::{Options, Server, Transport, run_recv, run_request, run_send, run_send_to};
use bitmule_client_common::{
    fountain::BLOCK_PLAIN,
    transfer::{Storage, TransferBuilder},
};
use bitmule_server::{AppState, router};
use tokio::sync::oneshot;

const RELAY: Options = Options { webrtc: false, relay: true, udp: false };
const WEBRTC: Options = Options { webrtc: true, relay: false, udp: false };
const UDP: Options = Options { webrtc: false, relay: false, udp: true };

async fn start_server() -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    let app = router(Arc::new(AppState::new()));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server { host, tls: false, stun: None }
}

fn payload(len: usize) -> Vec<u8> {
    (0..len as u32).map(|i| i.wrapping_mul(2654435761) as u8).collect()
}

/// Start a sender for `data`; returns its share link.
async fn start_sender(server: &Server, data: &[u8], options: Options) -> (bitmule_client_native::crypto::ShareLink, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let mut builder = TransferBuilder::new();
    builder.add_file(Storage::Bytes(data.to_vec().into()), Some("payload.bin".into()));
    let (manifest, transfer) = builder.commit_async().await.unwrap();

    let (link_tx, link_rx) = oneshot::channel();
    let server = server.clone();
    let sender = tokio::spawn(async move {
        run_send(&server, manifest, transfer, options, |link| {
            let _ = link_tx.send(link.clone());
        }).await
    });
    (link_rx.await.unwrap(), sender)
}

fn output() -> (tempfile::NamedTempFile, std::fs::File) {
    let out = tempfile::NamedTempFile::new().unwrap();
    let file = std::fs::OpenOptions::new().read(true).write(true).open(out.path()).unwrap();
    (out, file)
}

async fn roundtrip(len: usize, options: Options) -> Transport {
    let server = start_server().await;
    let data = payload(len);
    let (link, sender) = start_sender(&server, &data, options).await;

    let (out, file) = output();
    let report = run_recv(&server, &link, file, options).await.unwrap();
    assert_eq!(report.manifest.transfer_size, len as u64);

    tokio::time::timeout(std::time::Duration::from_secs(10), sender).await
        .expect("sender did not finish").unwrap().unwrap();
    assert_eq!(std::fs::read(out.path()).unwrap(), data);
    match report.transport {
        Transport::Relay => assert_eq!(report.relay_bytes, len as u64),
        // what the relay delivered before the hand-over is not sent again
        Transport::WebRtc => assert_eq!(report.relay_bytes + report.data_channel_bytes, len as u64),
        Transport::Udp => assert_eq!((report.udp_bytes, report.relay_bytes, report.data_channel_bytes), (len as u64, 0, 0)),
    }
    report.transport
}

#[tokio::test(flavor = "multi_thread")]
async fn small_file() {
    assert_eq!(roundtrip(1000, RELAY).await, Transport::Relay);
}

#[tokio::test(flavor = "multi_thread")]
async fn multi_piece_file() {
    roundtrip(300_000, RELAY).await;
}

/// Three blocks, the last one short.
#[tokio::test(flavor = "multi_thread")]
async fn multi_block_file() {
    roundtrip(BLOCK_PLAIN * 2 + 777, RELAY).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_file() {
    roundtrip(0, RELAY).await;
}

/// The data goes over a WebRTC data channel (on loopback here).
#[tokio::test(flavor = "multi_thread")]
async fn over_webrtc() {
    assert_eq!(roundtrip(BLOCK_PLAIN + 12345, WEBRTC).await, Transport::WebRtc);
}

/// The symbols go straight to the receiver over UDP (on loopback here).
#[tokio::test(flavor = "multi_thread")]
async fn over_udp() {
    assert_eq!(roundtrip(BLOCK_PLAIN * 2 + 12345, UDP).await, Transport::Udp);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_small_file_over_udp() {
    assert_eq!(roundtrip(1000, UDP).await, Transport::Udp);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_file_with_udp_on() {
    roundtrip(0, UDP).await;
}

/// UDP first, the relay as the way back; here UDP works.
#[tokio::test(flavor = "multi_thread")]
async fn udp_with_the_relay_behind_it() {
    let both = Options { webrtc: false, relay: true, udp: true };
    assert_eq!(roundtrip(BLOCK_PLAIN + 99, both).await, Transport::Udp);
}

/// One side cannot do UDP: the transfer goes over the relay.
#[tokio::test(flavor = "multi_thread")]
async fn udp_only_on_one_side_uses_the_relay() {
    let server = start_server().await;
    let data = payload(BLOCK_PLAIN + 1);
    let (link, sender) = start_sender(&server, &data, Options { webrtc: false, relay: true, udp: true }).await;

    let (out, file) = output();
    let report = run_recv(&server, &link, file, RELAY).await.unwrap();
    assert_eq!(report.transport, Transport::Relay);
    sender.await.unwrap().unwrap();
    assert_eq!(std::fs::read(out.path()).unwrap(), data);
}

/// Both transports on: whichever delivers, the file is right.
#[tokio::test(flavor = "multi_thread")]
async fn with_both_transports() {
    roundtrip(BLOCK_PLAIN * 2 + 5, Options::default()).await;
}

/// One side cannot do WebRTC: the transfer goes over the relay.
#[tokio::test(flavor = "multi_thread")]
async fn webrtc_only_on_one_side_uses_the_relay() {
    let server = start_server().await;
    let data = payload(BLOCK_PLAIN + 1);
    let (link, sender) = start_sender(&server, &data, Options::default()).await;

    let (out, file) = output();
    let report = run_recv(&server, &link, file, RELAY).await.unwrap();
    assert_eq!(report.transport, Transport::Relay);
    sender.await.unwrap().unwrap();
    assert_eq!(std::fs::read(out.path()).unwrap(), data);
}

/// One sender, three receivers on the same relay stream. They all get the
/// data from the same frames; whoever misses some is covered by later passes.
#[tokio::test(flavor = "multi_thread")]
async fn one_sender_three_receivers() {
    let len = BLOCK_PLAIN * 3 + 777;
    let server = start_server().await;
    let data = payload(len);
    let (link, sender) = start_sender(&server, &data, RELAY).await;

    // all three join together, so the sender sees them before any is done
    let outputs: Vec<_> = (0..3).map(|_| output()).collect();
    let receivers: Vec<_> = outputs.iter().map(|(_, file)| {
        let (server, link, file) = (server.clone(), link.clone(), file.try_clone().unwrap());
        tokio::spawn(async move { run_recv(&server, &link, file, RELAY).await })
    }).collect();

    for receiver in receivers {
        let report = tokio::time::timeout(std::time::Duration::from_secs(300), receiver).await
            .expect("receiver did not finish").unwrap().unwrap();
        assert_eq!(report.manifest.transfer_size, len as u64);
    }
    tokio::time::timeout(std::time::Duration::from_secs(30), sender).await
        .expect("sender did not finish").unwrap().unwrap();

    for (out, _) in &outputs {
        assert_eq!(std::fs::read(out.path()).unwrap(), data);
    }
}

/// One sender, three receivers, each with a data channel of its own.
#[tokio::test(flavor = "multi_thread")]
async fn one_sender_three_receivers_over_webrtc() {
    let len = BLOCK_PLAIN + 4321;
    let server = start_server().await;
    let data = payload(len);
    let (link, sender) = start_sender(&server, &data, WEBRTC).await;

    let outputs: Vec<_> = (0..3).map(|_| output()).collect();
    let receivers: Vec<_> = outputs.iter().map(|(_, file)| {
        let (server, link, file) = (server.clone(), link.clone(), file.try_clone().unwrap());
        tokio::spawn(async move { run_recv(&server, &link, file, WEBRTC).await })
    }).collect();

    for receiver in receivers {
        let report = tokio::time::timeout(std::time::Duration::from_secs(120), receiver).await
            .expect("receiver did not finish").unwrap().unwrap();
        assert_eq!(report.transport, Transport::WebRtc);
    }
    tokio::time::timeout(std::time::Duration::from_secs(30), sender).await
        .expect("sender did not finish").unwrap().unwrap();
    for (out, _) in &outputs {
        assert_eq!(std::fs::read(out.path()).unwrap(), data);
    }
}

/// Both transports on a transfer long enough for the data channel to open
/// part-way: whatever the relay delivered first is not fetched again.
#[tokio::test(flavor = "multi_thread")]
async fn starts_on_the_relay_and_moves_to_the_data_channel() {
    roundtrip(BLOCK_PLAIN * 12 + 5, Options::default()).await;
}

/// The receiver makes the request link; the sender answers it. The transfer
/// then runs as any other, signature check included.
async fn requested(len: usize, options: Options) -> Transport {
    let server = start_server().await;
    let data = payload(len);

    let (key_tx, key_rx) = oneshot::channel();
    let requester = {
        let server = server.clone();
        tokio::spawn(async move {
            run_request(&server, options, |key| { let _ = key_tx.send(key.clone()); }).await
        })
    };
    let key = key_rx.await.unwrap();

    let mut builder = TransferBuilder::new();
    builder.add_file(Storage::Bytes(data.clone().into()), Some("payload.bin".into()));
    let (manifest, transfer) = builder.commit_async().await.unwrap();
    let sender = {
        let server = server.clone();
        tokio::spawn(async move { run_send_to(&server, &key, manifest, transfer, options, |_| {}).await })
    };

    let link = tokio::time::timeout(std::time::Duration::from_secs(60), requester).await
        .expect("no share link from the sender").unwrap().unwrap();
    let (out, file) = output();
    let report = run_recv(&server, &link, file, options).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), sender).await
        .expect("sender did not finish").unwrap().unwrap();
    assert_eq!(std::fs::read(out.path()).unwrap(), data);
    report.transport
}

#[tokio::test(flavor = "multi_thread")]
async fn receiver_initiated_over_the_relay() {
    assert_eq!(requested(BLOCK_PLAIN + 99, RELAY).await, Transport::Relay);
}

#[tokio::test(flavor = "multi_thread")]
async fn receiver_initiated_over_webrtc() {
    assert_eq!(requested(BLOCK_PLAIN + 99, WEBRTC).await, Transport::WebRtc);
}

/// A sender that does not know the request key cannot join the rendezvous.
#[tokio::test(flavor = "multi_thread")]
async fn request_link_needs_the_right_key() {
    let server = start_server().await;
    let (key_tx, key_rx) = oneshot::channel();
    let requester = {
        let server = server.clone();
        tokio::spawn(async move {
            run_request(&server, RELAY, |key| { let _ = key_tx.send(key.clone()); }).await
        })
    };
    let mut key = key_rx.await.unwrap();

    // same session id is not guessable from another key, so a wrong key finds no session
    key.0[0] ^= 1;
    let mut builder = TransferBuilder::new();
    builder.add_file(Storage::Bytes(payload(10).into()), Some("payload.bin".into()));
    let (manifest, transfer) = builder.commit_async().await.unwrap();
    assert!(run_send_to(&server, &key, manifest, transfer, RELAY, |_| {}).await.is_err());
    assert!(!requester.is_finished(), "the requester keeps waiting");
    requester.abort();
}
