use std::{sync::Arc, time::Duration};

use bitmule_core::{
    ReceiverId, SessionId, Token,
    crypto::{PublicKey, SessionMac},
    pow,
    protocol::websocket::{ClientToServer, PeerCaps, ServerToClient},
};
use bitmule_server::{AppState, router};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn start() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(Arc::new(AppState::new()));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr.to_string()
}

async fn recv(ws: &mut Ws) -> Option<ServerToClient> {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("timeout")?;
        match msg.ok()? {
            Message::Binary(b) => return Some(postcard::from_bytes(&b).unwrap()),
            Message::Close(_) => return None,
            _ => {}
        }
    }
}

async fn send(ws: &mut Ws, msg: ClientToServer) {
    ws.send(Message::binary(postcard::to_stdvec(&msg).unwrap())).await.unwrap();
}

fn create_msg(id: ReceiverId, key: u8) -> ClientToServer {
    ClientToServer::CreateSession {
        id,
        capabilities: PeerCaps::RELAY,
        pub_key: PublicKey([key; 32]),
        mac: SessionMac([0; 32]),
    }
}

fn join_msg(id: ReceiverId, key: u8) -> ClientToServer {
    ClientToServer::JoinSession {
        id,
        capabilities: PeerCaps::RELAY,
        pub_key: PublicKey([key; 32]),
        mac: SessionMac([0; 32]),
    }
}

async fn connect_create(addr: &str, sid: &SessionId, token: Option<Token>) -> Ws {
    if let Some(t) = token {
        // reconnect: no PoW
        return connect_async(format!("ws://{addr}/ws/create?sid={}&token={}", sid.as_hex(), t.as_hex()))
            .await.unwrap().0;
    }
    #[derive(serde::Deserialize)]
    struct Pow { difficulty: u8, magic: u32 }
    let p: Pow = reqwest::Client::new().get(format!("http://{addr}/pow")).send().await.unwrap()
        .json().await.unwrap();
    let nonce = pow::solve_c(&sid.0, p.magic, p.difficulty);
    connect_async(format!("ws://{addr}/ws/create?sid={}&magic={}&pow={nonce}", sid.as_hex(), p.magic)).await.unwrap().0
}

async fn connect_join(addr: &str, sid: &SessionId) -> Ws {
    connect_async(format!("ws://{addr}/ws/join?sid={}", sid.as_hex())).await.unwrap().0
}

fn is_text(m: &Option<ServerToClient>) -> bool {
    matches!(m, Some(ServerToClient::Text(_)))
}

#[tokio::test]
async fn create_join_reconnect() {
    let addr = start().await;
    let sid = SessionId::random();
    let (owner_id, r1, r2) = (ReceiverId::random(), ReceiverId::random(), ReceiverId::random());

    let mut owner = connect_create(&addr, &sid, None).await;
    send(&mut owner, create_msg(owner_id, 1)).await;
    let Some(ServerToClient::SessionCreated { reconnect_token, relay_token: owner_relay }) = recv(&mut owner).await
        else { panic!("expected SessionCreated") };

    // second create without token is refused
    let mut dup = connect_create(&addr, &sid, None).await;
    send(&mut dup, create_msg(owner_id, 1)).await;
    assert!(is_text(&recv(&mut dup).await));
    // wrong token too
    let mut dup = connect_create(&addr, &sid, Some(Token::random())).await;
    send(&mut dup, create_msg(owner_id, 1)).await;
    assert!(is_text(&recv(&mut dup).await));

    // receiver joins; owner is told
    let mut rx1 = connect_join(&addr, &sid).await;
    send(&mut rx1, join_msg(r1, 2)).await;
    let Some(ServerToClient::SessionJoined { relay_token: r1_relay, sender_id, sender_pub_key, .. }) = recv(&mut rx1).await
        else { panic!("expected SessionJoined") };
    assert_eq!(sender_id, owner_id);
    assert_eq!(sender_pub_key.0, [1; 32]);
    assert!(matches!(recv(&mut owner).await, Some(ServerToClient::PeerJoined { id, .. }) if id == r1));

    // taking over the owner's id or an existing receiver's id is refused
    for id in [owner_id, r1] {
        let mut bad = connect_join(&addr, &sid).await;
        send(&mut bad, join_msg(id, 9)).await;
        assert!(is_text(&recv(&mut bad).await));
    }

    // relay auth
    let http = reqwest::Client::new();
    let url = |id: &ReceiverId, t: &Token| format!("http://{addr}/session/{}/{}?token={}", sid.as_hex(), id.as_hex(), t.as_hex());
    assert_eq!(http.get(url(&r1, &owner_relay)).send().await.unwrap().status(), 401);
    assert_eq!(http.get(url(&r2, &r1_relay)).send().await.unwrap().status(), 401);
    assert_eq!(http.post(url(&r1, &r1_relay)).send().await.unwrap().status(), 401);
    assert_eq!(http.get(url(&r1, &r1_relay)).send().await.unwrap().status(), 200);

    // owner drops; receiver can join meanwhile
    drop(owner);
    let mut rx2 = connect_join(&addr, &sid).await;
    send(&mut rx2, join_msg(r2, 3)).await;
    assert!(matches!(recv(&mut rx2).await, Some(ServerToClient::SessionJoined { .. })));

    // reconnect with the token: same tokens back, receivers replayed
    let mut owner = connect_create(&addr, &sid, Some(reconnect_token)).await;
    send(&mut owner, create_msg(owner_id, 1)).await;
    let Some(ServerToClient::SessionCreated { reconnect_token: t2, relay_token: rt2 }) = recv(&mut owner).await
        else { panic!("expected SessionCreated on reconnect") };
    assert!(t2 == reconnect_token && rt2 == owner_relay);
    let mut seen = vec![];
    for _ in 0..2 {
        let Some(ServerToClient::PeerJoined { id, .. }) = recv(&mut owner).await else { panic!() };
        seen.push(id);
    }
    assert!(seen.contains(&r1) && seen.contains(&r2));

    // a token can't create a session out of thin air
    let mut ghost = connect_create(&addr, &SessionId::random(), Some(reconnect_token)).await;
    send(&mut ghost, create_msg(owner_id, 1)).await;
    assert!(is_text(&recv(&mut ghost).await));

    // reconnect with a different identity key is refused
    let mut evil = connect_create(&addr, &sid, Some(reconnect_token)).await;
    send(&mut evil, create_msg(owner_id, 7)).await;
    assert!(is_text(&recv(&mut evil).await));

    // receiver leaves; owner is told
    drop(rx2);
    assert!(matches!(recv(&mut owner).await, Some(ServerToClient::PeerDisconnected { id }) if id == r2));
}
