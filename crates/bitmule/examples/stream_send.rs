//! Send one file as it is read — the path the app takes above a few MB.
//!
//! `cargo run --example stream_send -- <file> [server]`
//!
//! Nothing is copied or hashed first: the session is made, the link is
//! printed, and the bytes follow as they are read (the checksum comes last).
//! This exists so that path can be exercised against the live relay and the
//! browser viewer without the GUI.

use bitmule::v2::{self, Options, Server, StreamInfo, StreamSource};
use bitmule_core::protocol::websocket::TransferType;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = PathBuf::from(args.next().expect("usage: stream_send <file> [server]"));
    let server = Server::parse(&args.next().unwrap_or_else(|| "https://bitmule.net".into()));

    let size = std::fs::metadata(&path)?.len();
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
    let info = StreamInfo {
        typ: TransferType::SingleFile { compression: None },
        name,
        size_hint: Some(size),
    };
    let open = path.clone();
    let source = StreamSource::restartable(move || {
        let path = open.clone();
        Box::pin(async move {
            tokio::fs::File::open(&path).await.map(|f| Box::new(f) as v2::Reader)
        })
    });

    let shown = server.clone();
    let events: v2::OnSendEvent = std::sync::Arc::new(|event: v2::SendEvent| println!("event {event:?}"));

    v2::run_send_stream(
        &server,
        info,
        source,
        Options::default(),
        |link| println!("link {}", shown.link_url(link)),
        events,
    )
    .await
}
