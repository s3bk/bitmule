//! The `bitmule::Client` API (send / recv builders) end to end: an in-process
//! relay, files on disk, the share URL from the sender handed to the receiver.

use std::sync::{Arc, Mutex};

use bitmule::{Client, Error, TransportMode};
use bitmule_server::{AppState, router};

fn payload(len: usize) -> Vec<u8> {
    (0..len as u32).map(|i| i.wrapping_mul(2654435761) as u8).collect()
}

/// An in-process server; returns a client for it.
async fn client() -> Client {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(Arc::new(AppState::new()));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Client::new(format!("http://{addr}"))
}

#[tokio::test]
async fn one_file_keeps_its_name_and_content() {
    let client = client().await;
    let src = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    let data = payload(3 * 1024 * 1024 + 17);
    std::fs::write(src.path().join("photo.bin"), &data).unwrap();

    let handle = client.send(src.path().join("photo.bin")).mode(TransportMode::Relay).start().await.unwrap();
    assert_eq!(handle.display_name(), "photo.bin");
    assert_eq!(handle.total_bytes(), data.len() as u64);
    assert_eq!(handle.session_hex().len(), 64);
    assert!(handle.share_url().starts_with("http://127.0.0.1:"));

    let outcome = client.recv(handle.share_url()).dest(dest.path()).mode(TransportMode::Relay).start().await.unwrap();
    assert_eq!(outcome.len(), 1);
    let file = outcome.files().next().unwrap();
    assert_eq!(file.name(), "photo.bin");
    assert_eq!(file.size(), data.len() as u64);
    assert_eq!(file.read_all().await.unwrap(), data);
    assert_eq!(outcome.dest(), dest.path());
    handle.wait().await.unwrap();
}

#[tokio::test]
async fn send_with_name_renames_what_the_receiver_saves() {
    let client = client().await;
    let src = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("a.txt"), b"hello").unwrap();

    let handle = client.send_with_name(src.path().join("a.txt"), "secret.txt").mode(TransportMode::Relay).start().await.unwrap();
    assert_eq!(handle.display_name(), "secret.txt");
    let outcome = client.recv(handle.share_url()).dest(dest.path()).mode(TransportMode::Relay).start().await.unwrap();
    assert_eq!(outcome.files().next().unwrap().name(), "secret.txt");
    assert_eq!(std::fs::read(dest.path().join("secret.txt")).unwrap(), b"hello");
    handle.wait().await.unwrap();
}

#[tokio::test]
async fn several_files_arrive_unpacked() {
    let client = client().await;
    let src = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("one.txt"), b"first").unwrap();
    std::fs::write(src.path().join("two.bin"), payload(100_000)).unwrap();

    let handle = client
        .send(src.path().join("one.txt"))
        .send(src.path().join("two.bin"))
        .mode(TransportMode::Relay)
        .start()
        .await
        .unwrap();
    let outcome = client.recv(handle.share_url()).dest(dest.path()).mode(TransportMode::Relay).start().await.unwrap();
    let mut names: Vec<_> = outcome.files().map(|f| f.name().to_string()).collect();
    names.sort();
    assert_eq!(names, ["one.txt", "two.bin"]);
    for file in outcome.files() {
        match file.name() {
            "one.txt" => assert_eq!(file.read_all().await.unwrap(), b"first"),
            _ => assert_eq!(file.read_all().await.unwrap(), payload(100_000)),
        }
        assert!(file.path().starts_with(dest.path()));
    }
    // the zip itself is gone, the files are in a folder
    assert!(std::fs::read_dir(dest.path()).unwrap().flatten().all(|e| e.path().is_dir()));
    handle.wait().await.unwrap();
}

#[tokio::test]
async fn a_directory_keeps_its_layout() {
    let client = client().await;
    let src = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    let dir = src.path().join("album");
    std::fs::create_dir_all(dir.join("sub/deeper")).unwrap();
    std::fs::write(dir.join("top.txt"), b"top").unwrap();
    std::fs::write(dir.join("sub/mid.txt"), b"mid").unwrap();
    std::fs::write(dir.join("sub/deeper/low.txt"), b"low").unwrap();

    let handle = client.send(&dir).mode(TransportMode::Relay).start().await.unwrap();
    let outcome = client.recv(handle.share_url()).dest(dest.path()).mode(TransportMode::Relay).start().await.unwrap();
    assert_eq!(outcome.len(), 3);
    let mut relative: Vec<_> = outcome
        .files()
        .map(|f| f.path().strip_prefix(dest.path()).unwrap().components().skip(1).collect::<std::path::PathBuf>())
        .collect();
    relative.sort();
    assert_eq!(
        relative,
        [
            std::path::PathBuf::from("album/sub/deeper/low.txt"),
            std::path::PathBuf::from("album/sub/mid.txt"),
            std::path::PathBuf::from("album/top.txt"),
        ]
    );
    handle.wait().await.unwrap();
}

#[tokio::test]
async fn progress_reaches_the_total_on_both_sides() {
    let client = client().await;
    let src = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    let data = payload(6 * 1024 * 1024);
    std::fs::write(src.path().join("big.bin"), &data).unwrap();

    let sent = Arc::new(Mutex::new((0u64, 0u64)));
    let received = Arc::new(Mutex::new((0u64, 0u64, String::new())));
    let handle = client
        .send(src.path().join("big.bin"))
        .mode(TransportMode::Relay)
        .on_progress({
            let sent = sent.clone();
            move |bytes, total| *sent.lock().unwrap() = (bytes, total)
        })
        .start()
        .await
        .unwrap();
    client
        .recv(handle.share_url())
        .dest(dest.path())
        .mode(TransportMode::Relay)
        .on_progress({
            let received = received.clone();
            move |bytes, total, name| *received.lock().unwrap() = (bytes, total, name.to_string())
        })
        .start()
        .await
        .unwrap();
    handle.wait().await.unwrap();

    let (bytes, total, name) = received.lock().unwrap().clone();
    assert_eq!((bytes, total), (data.len() as u64, data.len() as u64));
    assert_eq!(name, "big.bin");
    // the sender hears what the receiver reports; the last report may lag a little
    let (bytes, total) = *sent.lock().unwrap();
    assert_eq!(total, data.len() as u64);
    assert!(bytes > 0 && bytes <= total, "sender saw {bytes}/{total}");
}

#[tokio::test]
async fn a_second_file_with_the_same_name_does_not_overwrite() {
    let client = client().await;
    let src = tempfile::tempdir().unwrap();
    let dest = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("note.txt"), b"v1").unwrap();
    for _ in 0..2 {
        let handle = client.send(src.path().join("note.txt")).mode(TransportMode::Relay).start().await.unwrap();
        client.recv(handle.share_url()).dest(dest.path()).mode(TransportMode::Relay).start().await.unwrap();
        handle.wait().await.unwrap();
    }
    assert!(dest.path().join("note.txt").exists());
    assert!(dest.path().join("note (1).txt").exists());
}

#[tokio::test]
async fn bad_input_is_reported_not_panicked() {
    let client = client().await;
    let dest = tempfile::tempdir().unwrap();

    assert!(matches!(client.send("/definitely/not/here").start().await, Err(Error::Transport(_))));
    assert!(matches!(client.recv("https://example.net/#nope").dest(dest.path()).start().await, Err(Error::BadShareUrl(_))));
    assert!(matches!(client.recv("").dest(dest.path()).start().await, Err(Error::BadShareUrl(_))));

    let empty = tempfile::tempdir().unwrap();
    assert!(matches!(client.send(empty.path()).start().await, Err(Error::Transport(_))));
}

#[tokio::test]
async fn an_unreachable_server_fails_the_start() {
    // nothing listens on this port
    let client = Client::new("http://127.0.0.1:9");
    let src = tempfile::tempdir().unwrap();
    std::fs::write(src.path().join("x"), b"x").unwrap();
    let result = client.send(src.path().join("x")).mode(TransportMode::Relay).start().await;
    assert!(matches!(result, Err(Error::Transport(_))), "got {:?}", result.map(|h| h.share_url().to_string()));
}

#[test]
fn the_builder_defaults() {
    let client = Client::builder().build();
    assert_eq!(client.server(), "https://bitmule.qdat.net");
    let client = Client::builder().server("http://localhost:1").build();
    assert_eq!(client.server(), "http://localhost:1");
}
