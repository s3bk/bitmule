use std::time::Duration;

use bitmule_core::protocol::websocket::{ClientToServer, ServerToClient};
use bytes::Bytes;
use futures::SinkExt;
use tokio::{select, spawn, sync::mpsc, time::{Instant, interval, interval_at}};
use tokio_stream::StreamExt;
use tokio_tungstenite::connect_async;
use tungstenite::Message;


/// Connect and start the worker that owns the socket. Messages go in through
/// the sender and come out of the receiver. The worker finishes once every
/// sender is dropped and the queued messages are written, so awaiting the
/// handle after that is a flush.
pub async fn connect_ws(url: &str) -> Result<(mpsc::Sender<ClientToServer>, mpsc::Receiver<ServerToClient>, tokio::task::JoinHandle<Result<(), anyhow::Error>>), anyhow::Error> {
    let mut ws = if crate::nic::get().is_some() {
        let uri: tungstenite::http::Uri = url.parse()?;
        let host = uri.host().ok_or_else(|| anyhow::anyhow!("no host in {url}"))?;
        let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("wss") { 443 } else { 80 });
        let stream = crate::nic::connect_tcp(host, port).await?;
        tokio_tungstenite::client_async_tls(url, stream).await?.0
    } else {
        connect_async(url).await?.0
    };

    let (out_tx, mut rx) = mpsc::channel(16);
    let (tx, out_rx) = mpsc::channel(16);

    let keepalive_interval = Duration::new(5, 0);
    let start = Instant::now() + keepalive_interval;
    let mut keepalive = interval_at(start, keepalive_interval);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let worker = spawn(async move {
        loop {
            select! {
                msg = ws.next() => {
                    match msg {
                        Some(Ok(Message::Binary(bytes))) => {
                            let data = postcard::from_bytes::<ServerToClient>(&*bytes)?;
                            tx.send(data).await?;
                        }
                        // tungstenite answers pings itself
                        Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Text(_) | Message::Frame(_))) => {}
                        _ => break
                    }
                }
                msg = rx.recv() => {
                    match msg {
                        Some(msg) => {
                            let data = postcard::to_stdvec(&msg).unwrap();
                            ws.send(Message::binary(data)).await?;
                        }
                        None => break
                    }
                }
                _ = keepalive.tick() => {
                    ws.send(Message::Ping(Bytes::new())).await?;
                }
            }
        }
        let _ = ws.close(None).await;
        Result::<(), anyhow::Error>::Ok(())
    });

    Ok((out_tx, out_rx, worker))
}
