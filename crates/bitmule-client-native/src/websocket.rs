use std::time::Duration;

use bitmule_core::protocol::websocket::{ClientToServer, ServerToClient};
use bytes::Bytes;
use futures::SinkExt;
use tokio::{select, spawn, sync::mpsc, time::{Instant, interval, interval_at}};
use tokio_stream::StreamExt;
use tokio_tungstenite::connect_async;
use tungstenite::Message;


pub async fn connect_ws(url: &str) -> Result<(mpsc::Sender<ClientToServer>, mpsc::Receiver<ServerToClient>), anyhow::Error> {
    let (mut ws, resp) = connect_async(url).await?;

    let (out_tx, mut rx) = mpsc::channel(16);
    let (tx, out_rx) = mpsc::channel(16);

    let keepalive_interval = Duration::new(5, 0);
    let start = Instant::now() + keepalive_interval;
    let mut keepalive = interval_at(start, keepalive_interval);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    spawn(async move {
        loop {
            select! {
                msg = ws.next() => {
                    match msg {
                        Some(Ok(Message::Binary(bytes))) => {
                            let data = postcard::from_bytes::<ServerToClient>(&*bytes)?;
                            tx.send(data).await?;
                        }
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
        Result::<(), anyhow::Error>::Ok(())
    });

    Ok((out_tx, out_rx))
}
