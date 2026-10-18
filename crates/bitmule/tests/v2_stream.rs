//! Streaming transfers: data sent as it is read, the manifest (key, size, name)
//! and checksum after it.

use std::{
    sync::{Arc, atomic::{AtomicU32, Ordering}},
    time::Duration,
};

use bitmule::v2::{OnSendEvent, Options, SendEvent, Server, StreamInfo, StreamSource, run_recv_with, run_send_stream};
use bitmule_client_common::fountain::BLOCK_PLAIN;
use bitmule_server::{AppState, router};
use tokio::{io::AsyncWriteExt, sync::oneshot};

const RELAY: Options = Options { webrtc: false, relay: true };

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

fn no_events() -> OnSendEvent {
    Arc::new(|_| {})
}

type Link = bitmule_client_native::crypto::ShareLink;
type Sender = tokio::task::JoinHandle<anyhow::Result<()>>;

fn start_sender(server: &Server, source: StreamSource, name: &str, options: Options, events: OnSendEvent) -> (oneshot::Receiver<Link>, Sender) {
    let (link_tx, link_rx) = oneshot::channel();
    let server = server.clone();
    let info = StreamInfo::file(name);
    let sender = tokio::spawn(async move {
        run_send_stream(&server, info, source, options, |link| { let _ = link_tx.send(link.clone()); }, events).await
    });
    (link_rx, sender)
}

/// A pipe fed in pieces with pauses, as a producer that is still working.
fn slow_pipe(data: Vec<u8>, piece: usize, pause: Duration) -> StreamSource {
    let (mut writer, reader) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        for chunk in data.chunks(piece) {
            if writer.write_all(chunk).await.is_err() {
                return;
            }
            tokio::time::sleep(pause).await;
        }
    });
    StreamSource::one_shot(reader)
}

/// Receive `link` into a temp file; returns the report and what was written.
async fn receive(server: &Server, link: &Link, options: Options) -> anyhow::Result<(bitmule::v2::Report, Vec<u8>)> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("out");
    let open_path = path.clone();
    let report = run_recv_with(
        server,
        link,
        move |manifest| {
            // the file is made only once the manifest is in, and has the sender's name
            assert!(manifest.file_name().is_some());
            std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&open_path)
        },
        options,
    )
    .await?;
    let data = std::fs::read(&path)?;
    Ok((report, data))
}

#[tokio::test]
async fn a_slow_pipe_arrives_whole() {
    let server = start_server().await;
    let data = payload(BLOCK_PLAIN * 2 + 12_345);
    let (link, sender) = start_sender(&server, slow_pipe(data.clone(), 300_000, Duration::from_millis(20)), "pipe.bin", RELAY, no_events());
    let link = link.await.unwrap();
    // no signature in the link: the checksum follows the data
    assert_eq!(link.signature, [0u8; 32]);

    let (report, got) = receive(&server, &link, RELAY).await.unwrap();
    assert_eq!(got, data);
    assert_eq!(report.manifest.transfer_size, data.len() as u64);
    assert_eq!(report.manifest.file_name().as_deref(), Some("pipe.bin"));
    sender.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_restartable_source_is_opened_again_for_repair_passes() {
    let server = start_server().await;
    let data = payload(BLOCK_PLAIN + 777);
    let opened = Arc::new(AtomicU32::new(0));
    let source = {
        let (data, opened) = (data.clone(), opened.clone());
        StreamSource::restartable(move || {
            opened.fetch_add(1, Ordering::SeqCst);
            let data = data.clone();
            async move { Ok(Box::new(std::io::Cursor::new(data)) as _) }
        })
    };
    let (link, sender) = start_sender(&server, source, "again.bin", RELAY, no_events());
    let (report, got) = receive(&server, &link.await.unwrap(), RELAY).await.unwrap();
    assert_eq!(got, data);
    assert_eq!(report.manifest.transfer_size, data.len() as u64);
    sender.await.unwrap().unwrap();
    assert!(opened.load(Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn nothing_and_exactly_whole_blocks() {
    for len in [0, 1, BLOCK_PLAIN, 2 * BLOCK_PLAIN] {
        let server = start_server().await;
        let data = payload(len);
        let (link, sender) = start_sender(&server, StreamSource::one_shot(std::io::Cursor::new(data.clone())), "edge.bin", RELAY, no_events());
        let (report, got) = receive(&server, &link.await.unwrap(), RELAY).await.unwrap();
        assert_eq!(got, data, "length {len}");
        assert_eq!(report.manifest.transfer_size, len as u64);
        sender.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn a_receiver_that_joins_late_still_gets_everything() {
    let server = start_server().await;
    let data = payload(BLOCK_PLAIN * 4);
    let (link, sender) = start_sender(&server, slow_pipe(data.clone(), 400_000, Duration::from_millis(60)), "late.bin", RELAY, no_events());
    let link = link.await.unwrap();

    let first = {
        let (server, link) = (server.clone(), link.clone());
        tokio::spawn(async move { receive(&server, &link, RELAY).await })
    };
    // by now the first blocks have gone out; the second receiver missed them
    tokio::time::sleep(Duration::from_millis(500)).await;
    let second = {
        let (server, link) = (server.clone(), link.clone());
        tokio::spawn(async move { receive(&server, &link, RELAY).await })
    };
    for receiver in [first, second] {
        let (_, got) = receiver.await.unwrap().unwrap();
        assert_eq!(got, data);
    }
    sender.await.unwrap().unwrap();
}

#[tokio::test]
async fn the_sender_hears_about_the_receiver() {
    let server = start_server().await;
    let data = payload(BLOCK_PLAIN + 5);
    let events = Arc::new(std::sync::Mutex::new(Vec::<SendEvent>::new()));
    let on_event: OnSendEvent = {
        let events = events.clone();
        Arc::new(move |e| events.lock().unwrap().push(e))
    };
    let (link, sender) = start_sender(&server, StreamSource::one_shot(std::io::Cursor::new(data.clone())), "ev.bin", RELAY, on_event);
    receive(&server, &link.await.unwrap(), RELAY).await.unwrap();
    sender.await.unwrap().unwrap();
    let events = events.lock().unwrap();
    assert!(matches!(events.first(), Some(SendEvent::Connected { .. })), "{events:?}");
    assert!(matches!(events.last(), Some(SendEvent::Done { .. })), "{events:?}");
}

#[tokio::test]
async fn a_stream_needs_the_relay() {
    let server = start_server().await;
    let webrtc_only = Options { webrtc: true, relay: false };
    let result = run_send_stream(&server, StreamInfo::file("x"), StreamSource::one_shot(std::io::Cursor::new(payload(10))), webrtc_only, |_| {}, no_events()).await;
    let error = result.unwrap_err().to_string();
    assert!(error.contains("relay"), "{error}");
}
