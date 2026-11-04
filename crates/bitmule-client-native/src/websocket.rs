use std::time::Duration;

use bitmule_core::{Token, protocol::websocket::{ClientToServer, ServerToClient}};
use bytes::Bytes;
use futures::SinkExt;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    select, spawn,
    sync::mpsc,
    time::{Instant, interval_at, sleep},
};
use tokio_stream::StreamExt;
use tokio_tungstenite::connect_async;
use tungstenite::Message;

type Outbox = mpsc::Sender<ClientToServer>;
type Inbox = mpsc::Receiver<ServerToClient>;
type Worker = tokio::task::JoinHandle<Result<(), anyhow::Error>>;

/// How often the client pings on a quiet socket. Browsers cannot send
/// websocket pings, which is why the server offers to ping for them; this is
/// for everyone else, and for proxies that drop a connection that stays quiet.
const KEEPALIVE: Duration = Duration::from_secs(5);

/// Longest wait between two attempts to get a dropped socket back. The
/// attempts itself are `MAX_RECONNECTS` long, so a transfer survives a
/// network outage of about `MAX_RECONNECTS * MAX_RECONNECT_DELAY`.
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(8);

/// Attempts to get a dropped socket back before giving up. Each one starts
/// over from zero once a connection made it back into the session.
const MAX_RECONNECTS: u32 = 10;

/// Connect and start the worker that owns the socket. Messages go in through
/// the sender and come out of the receiver. The worker finishes once every
/// sender is dropped and the queued messages are written, so awaiting the
/// handle after that is a flush.
pub async fn connect_ws(url: &str) -> Result<(Outbox, Inbox, Worker), anyhow::Error> {
    let mut ws = open(url).await?;
    let (out_tx, mut rx) = mpsc::channel(16);
    let (tx, out_rx) = mpsc::channel(16);

    let worker = spawn(async move {
        let mut keepalive = keepalive();
        let mut token = None;
        let mut registered = false;
        let _ = talk(&mut ws, &tx, &mut rx, &mut keepalive, &mut token, &mut registered).await;
        let _ = ws.close(None).await;
        Result::<(), anyhow::Error>::Ok(())
    });

    Ok((out_tx, out_rx, worker))
}

/// How the owner of a session gets its socket back after it drops: the server
/// keeps the owner's place in the room and lets it in again with the
/// reconnect token from `SessionCreated`, without a new proof of work.
pub struct Owner {
    /// `/ws/create?sid=…`: the socket URL without the proof-of-work part,
    /// which only the first connection needs. Later ones carry `&token=`.
    pub url: String,
    /// The hello (`CreateSession`) to send on every (re)connect.
    pub hello: Box<dyn Fn() -> ClientToServer + Send + Sync>,
}

/// Connect as the owner of a session, and stay connected: if the socket drops,
/// the worker redials `/ws/create` with the reconnect token, sends the hello
/// again, and carries on feeding the same channels. The server answers with
/// `SessionCreated` and replays the receivers that joined meanwhile, so the
/// peers of this session stay reachable across the drop.
///
/// `first` is the URL of the first connection (with magic and proof of work);
/// `owner.url` is the same URL without them.
pub async fn connect_ws_owner(first: &str, owner: Owner) -> Result<(Outbox, Inbox, Worker), anyhow::Error> {
    let ws = open(first).await?;
    let (out_tx, mut rx) = mpsc::channel(16);
    let (tx, out_rx) = mpsc::channel(16);

    let worker = spawn(async move {
        let mut keepalive = keepalive();
        let mut token: Option<Token> = None;
        let mut socket = Some(ws);
        let mut failed: u32 = 0;

        loop {
            let mut ws = match socket.take() {
                Some(ws) => ws,
                None => {
                    let Some(token) = token else { break };
                    if failed >= MAX_RECONNECTS {
                        tracing::error!("gave up reconnecting to {} after {failed} attempts", owner.url);
                        break;
                    }
                    let delay = reconnect_delay(failed);
                    failed += 1;
                    tracing::info!("socket to {} dropped; reconnect {failed}/{MAX_RECONNECTS} in {delay:?}", owner.url);
                    sleep(delay).await;
                    match open(&format!("{}&token={}", owner.url, token.as_hex())).await {
                        Ok(ws) => ws,
                        Err(e) => {
                            tracing::warn!("reconnect to {} failed: {e}", owner.url);
                            continue;
                        }
                    }
                }
            };

            let hello = (owner.hello)();
            let hello = match postcard::to_stdvec(&hello) {
                Ok(hello) => hello,
                Err(e) => {
                    tracing::error!("cannot send the session hello: {e}");
                    break;
                }
            };
            if ws.send(Message::binary(hello)).await.is_err() {
                // the socket was already dead; go straight to the redial
                continue;
            }

            let mut registered = false;
            let end = talk(&mut ws, &tx, &mut rx, &mut keepalive, &mut token, &mut registered).await;
            let _ = ws.close(None).await;
            if registered {
                failed = 0;
            }
            match end {
                Ok(End::Done) => break,
                // the server turned us away (session gone, token stale): no
                // point in redialling, the answer was a reason, not a timeout
                Ok(End::Dropped) | Err(_) => {}
            }
        }
        Result::<(), anyhow::Error>::Ok(())
    });

    Ok((out_tx, out_rx, worker))
}

/// How one connection ended.
#[derive(Debug, PartialEq, Eq)]
enum End {
    /// The socket dropped; if this is the owner, it may be worth redialling.
    Dropped,
    /// Nothing more to send (the caller dropped its sender), or the server
    /// turned us away: the worker is done.
    Done,
}

fn keepalive() -> tokio::time::Interval {
    let mut keepalive = interval_at(Instant::now() + KEEPALIVE, KEEPALIVE);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive
}

/// 0, 250 ms, 500 ms, 1 s, 2 s, 4 s, then 8 s for every further attempt.
fn reconnect_delay(attempt: u32) -> Duration {
    if attempt == 0 {
        return Duration::ZERO;
    }
    let millis = 250u64.saturating_mul(1 << (attempt - 1).min(5));
    Duration::from_millis(millis).min(MAX_RECONNECT_DELAY)
}

/// Talk on one connection until it ends. Registers `token` as soon as the
/// server hands one out, and `registered` once we are in the session.
async fn talk<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    tx: &mpsc::Sender<ServerToClient>,
    rx: &mut mpsc::Receiver<ClientToServer>,
    keepalive: &mut tokio::time::Interval,
    token: &mut Option<Token>,
    registered: &mut bool,
) -> Result<End, anyhow::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        select! {
            msg = ws.next() => {
                match msg {
                    Some(Ok(Message::Binary(bytes))) => {
                        let data = postcard::from_bytes::<ServerToClient>(&bytes)?;
                        match &data {
                            ServerToClient::SessionCreated { reconnect_token, .. } => {
                                *token = Some(*reconnect_token);
                                *registered = true;
                            }
                            ServerToClient::SessionJoined { .. } => *registered = true,
                            // the server says why it will not have us; that is
                            // an answer, so pass it on and stop
                            ServerToClient::Text(_) if !*registered => {
                                let _ = tx.send(data).await;
                                return Ok(End::Done);
                            }
                            _ => {}
                        }
                        if tx.send(data).await.is_err() {
                            return Ok(End::Done);
                        }
                    }
                    // tungstenite answers pings itself
                    Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Text(_) | Message::Frame(_))) => {}
                    Some(Ok(Message::Close(_))) => return Ok(End::Dropped),
                    Some(Err(e)) => {
                        tracing::debug!("websocket: {e}");
                        return Ok(End::Dropped);
                    }
                    None => return Ok(End::Dropped),
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(msg) => {
                        if *registered || matches!(msg, ClientToServer::CreateSession { .. } | ClientToServer::JoinSession { .. }) {
                            let data = postcard::to_stdvec(&msg).unwrap();
                            if ws.send(Message::binary(data)).await.is_err() {
                                return Ok(End::Dropped);
                            }
                        }
                    }
                    // every sender is gone and everything is written
                    None => return Ok(End::Done),
                }
            }
            _ = keepalive.tick() => {
                if ws.send(Message::Ping(Bytes::new())).await.is_err() {
                    return Ok(End::Dropped);
                }
            }
        }
    }
}

/// Connect to `url`, honouring the selected network interface.
async fn open(url: &str) -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, anyhow::Error> {
    let ws = if crate::nic::get().is_some() {
        let uri: tungstenite::http::Uri = url.parse()?;
        let host = uri.host().ok_or_else(|| anyhow::anyhow!("no host in {url}"))?;
        let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("wss") { 443 } else { 80 });
        let stream = crate::nic::connect_tcp(host, port).await?;
        tokio_tungstenite::client_async_tls(url, stream).await?.0
    } else {
        connect_async(url).await?.0
    };
    Ok(ws)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitmule_core::{ReceiverId, Token};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_hdr_async;
    use tungstenite::handshake::server::{Request, Response};

    fn hello_frame() -> ClientToServer {
        ClientToServer::CreateSession {
            id: ReceiverId::random(),
            capabilities: bitmule_core::protocol::websocket::PeerCaps::RELAY,
            pub_key: bitmule_crypto::PublicKey([7; 32]),
            mac: bitmule_crypto::SessionMac([8; 32]),
            join_check: [9; 32],
        }
    }

    fn binary(msg: &ServerToClient) -> Message {
        Message::binary(postcard::to_stdvec(msg).unwrap())
    }

    /// A dropped socket is redialled with the token from `SessionCreated`,
    /// and what the server replays afterwards reaches the same receiver.
    #[tokio::test]
    async fn owner_reconnects_with_its_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let urls: Arc<Mutex<Vec<String>>> = Default::default();
        let token = Token::random();
        let peer = ReceiverId::random();

        let seen = urls.clone();
        let server = tokio::spawn(async move {
            let record = move |req: &Request, res: Response| {
                seen.lock().unwrap().push(req.uri().to_string());
                Ok(res)
            };
            // first connection: hand out the token, then drop the socket
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = accept_hdr_async(stream, record.clone()).await.unwrap();
            assert!(matches!(ws.next().await, Some(Ok(Message::Binary(_)))));
            ws.send(binary(&ServerToClient::SessionCreated { reconnect_token: token, relay_token: Token::random() })).await.unwrap();
            ws.close(None).await.unwrap();
            drop(ws);

            // second connection: the same session, with something to say
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = accept_hdr_async(stream, record.clone()).await.unwrap();
            assert!(matches!(ws.next().await, Some(Ok(Message::Binary(_)))));
            ws.send(binary(&ServerToClient::SessionCreated { reconnect_token: token, relay_token: Token::random() })).await.unwrap();
            ws.send(binary(&ServerToClient::PeerJoined {
                id: peer,
                pub_key: bitmule_crypto::PublicKey([1; 32]),
                mac: bitmule_crypto::SessionMac([2; 32]),
                caps: bitmule_core::protocol::websocket::PeerCaps::RELAY,
            })).await.unwrap();
            // keep the socket open until the client is done
            let _ = ws.next().await;
            token
        });

        let url = format!("ws://{addr}/ws/create?sid=00&enablePing");
        let (to_server, mut from_server, worker) = connect_ws_owner(
            &format!("{url}&magic=1&pow=2"),
            Owner { url, hello: Box::new(hello_frame) },
        ).await.unwrap();

        // the first SessionCreated comes off the first connection
        assert!(matches!(from_server.recv().await, Some(ServerToClient::SessionCreated { .. })));
        // after the drop, the replayed traffic of the second one
        let replayed = tokio::time::timeout(Duration::from_secs(10), from_server.recv()).await.unwrap();
        match replayed {
            Some(ServerToClient::SessionCreated { reconnect_token, .. }) => assert_eq!(reconnect_token, token),
            _ => panic!("expected the reconnect's SessionCreated"),
        }
        match tokio::time::timeout(Duration::from_secs(10), from_server.recv()).await.unwrap() {
            Some(ServerToClient::PeerJoined { id, .. }) => assert_eq!(id, peer),
            _ => panic!("expected the replayed PeerJoined"),
        }
        drop(to_server);
        assert!(tokio::time::timeout(Duration::from_secs(10), worker).await.unwrap().is_ok());
        server.await.unwrap();

        let urls = urls.lock().unwrap();
        assert_eq!(urls.len(), 2, "{urls:?}");
        assert!(urls[0].contains("pow=2") && !urls[0].contains("token="), "{}", urls[0]);
        assert!(urls[1].contains(&format!("token={}", token.as_hex())), "{}", urls[1]);
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(reconnect_delay(0), Duration::ZERO);
        assert_eq!(reconnect_delay(1), Duration::from_millis(250));
        assert_eq!(reconnect_delay(2), Duration::from_millis(500));
        assert_eq!(reconnect_delay(9), MAX_RECONNECT_DELAY);
    }
}
