//! Relay for the bulk data stream: one sender POSTs frames, any number of
//! receivers GET them.
//!
//! The data is fountain coded, so receivers are interchangeable. Every
//! frame is offered to all connected receivers; a receiver whose queue is
//! full misses that frame. The sender is only held back while *no* receiver
//! can take the frame, so the rate follows the fastest receiver (and a lone
//! receiver never loses a frame). With no receiver connected the sender
//! blocks until one connects.
//!
//! Frame format (sender -> relay)
//! - 2 bytes payload length n (LE)
//! - 1 byte frame type
//! - n bytes payload
//!
//! Data (type 1) is the only frame type. Frames are relayed whole, header
//! included, so a receiver can split the byte stream back into frames.

use std::{borrow::Cow, collections::HashMap, convert::Infallible, io, pin::Pin, sync::{Arc, Mutex as StdMutex, atomic::{AtomicU64, Ordering}}, task::{Context, Poll}};

use axum::{body::{Body, BodyDataStream}, extract::{Path, Query, State}, response::IntoResponse};
use bytes::{Buf, Bytes, BytesMut};
use futures::TryStreamExt;
use futures_util::{Stream, StreamExt};
use tokio::{pin, select, sync::{Notify, mpsc}};
use tokio_util::{codec::{Decoder, FramedRead}, io::StreamReader};
use bitmule_core::{ReceiverId, SessionId, Token, protocol::relay_frame::*};

use crate::{AppState, state::SessionState};

/// Frames queued per receiver before it starts missing frames.
const RECEIVER_QUEUE_DEPTH: usize = 8;

struct FrameDecoder;

impl Decoder for FrameDecoder {
    type Item = (u8, Bytes);
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.remaining() < 1 + FRAME_SIZE_BYTES { return Ok(None); }  // type(1) + len(FRAME_SIZE_BYTES)

        let frame_length = FrameSize::from_le_bytes(src[0..FRAME_SIZE_BYTES].try_into().unwrap()) as usize;
        let frame_type = src[FRAME_SIZE_BYTES];

        if src.remaining() < 1 + FRAME_SIZE_BYTES + frame_length as usize {
            return Ok(None);
        }
        // keep the header: receivers use it to find frame boundaries
        let frame = src.split_to(1 + FRAME_SIZE_BYTES + frame_length).freeze();
        Ok(Some((frame_type, frame)))
    }
}

#[derive(Debug)]
pub enum Error {
    BadSessionId,
    BadReceiverId,
    SessionNotFound,
    Unauthorized,
    Io(io::Error),
    InvalidFrameType(u8),
    Closed,
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        let (status, body): (StatusCode, Cow<str>) = match self {
            Error::Io(_e) => (StatusCode::BAD_REQUEST, "Io Error".into()),
            Error::InvalidFrameType(t) => (StatusCode::BAD_REQUEST, format!("invalid frame type: {t}").into()),
            Error::Closed => (StatusCode::SERVICE_UNAVAILABLE, "session closed".into()),
            Error::BadSessionId => (StatusCode::BAD_REQUEST, "Invalid Session ID".into()),
            Error::BadReceiverId => (StatusCode::BAD_REQUEST, "Invalid Receiver ID".into()),
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "Invalid relay token".into()),
            Error::SessionNotFound => (StatusCode::NOT_FOUND, "Session ID not found".into()),
        };
        (status, body).into_response()
    }
}

pub struct MulticastSession {
    /// Connected relay GETs. The generation tells a stream's drop whether
    /// the entry is still its own or was replaced by a reconnect.
    receivers: StdMutex<HashMap<ReceiverId, (u64, mpsc::Sender<Bytes>)>>,
    next_generation: AtomicU64,
    /// Generation of the active sender stream; a newer POST replaces it.
    sender_generation: AtomicU64,
    /// Woken when a receiver connects or a sender is replaced.
    changed: Notify,
}
impl Default for MulticastSession {
    fn default() -> Self {
        MulticastSession {
            receivers: Default::default(),
            next_generation: AtomicU64::new(0),
            sender_generation: AtomicU64::new(0),
            changed: Notify::new(),
        }
    }
}

impl MulticastSession {
    /// Offer `data` to every receiver. Waits until at least one took it.
    /// Returns false if this sender was replaced meanwhile.
    async fn broadcast(&self, data: &Bytes, generation: u64) -> bool {
        loop {
            // register for wake-ups before looking, so none is missed
            let changed = self.changed.notified();
            pin!(changed);
            changed.as_mut().enable();

            if self.sender_generation.load(Ordering::Acquire) != generation {
                return false;
            }
            let senders: Vec<_> = self.receivers.lock().unwrap().values().map(|(_, tx)| tx.clone()).collect();
            let mut accepted = false;
            for tx in &senders {
                accepted |= tx.try_send(data.clone()).is_ok();
            }
            if accepted {
                return true;
            }

            // Nobody had room (or nobody is connected): wait for a receiver
            // to drain, a new one to connect, or for this sender to be replaced.
            if senders.is_empty() {
                changed.await;
            } else {
                let room = futures::future::select_all(
                    senders.iter().map(|tx| Box::pin(async move { let _ = tx.reserve().await; }))
                );
                select! {
                    _ = changed => {}
                    _ = room => {}
                }
            }
        }
    }
}

pub async fn run_session(state: Arc<SessionState>, stream: BodyDataStream) -> Result<(), Error> {
    let session = state.multicast();
    let generation = session.sender_generation.fetch_add(1, Ordering::AcqRel) + 1;
    // kick the previous sender out of its wait
    session.changed.notify_waiters();

    let reader = StreamReader::new(stream.map_err(io::Error::other));
    let stream = FramedRead::new(reader, FrameDecoder);
    pin!(stream);

    while let Some(next) = stream.next().await {
        let (frame_type, data) = next?;

        match frame_type {
            F_DATA => {
                if !session.broadcast(&data, generation).await {
                    return Err(Error::Closed);
                }
            }
            _ => return Err(Error::InvalidFrameType(frame_type)),
        }
    }

    Ok(())
}

pub async fn add_receiver(state: Arc<SessionState>, reciever_id: ReceiverId) -> Body {
    let (tx, rx) = mpsc::channel(RECEIVER_QUEUE_DEPTH);
    let multicast = state.multicast();
    let generation = multicast.next_generation.fetch_add(1, Ordering::Relaxed);
    // replacing an old entry drops its sender, which ends the old stream
    multicast.receivers.lock().unwrap().insert(reciever_id, (generation, tx));
    multicast.changed.notify_waiters();

    Body::from_stream(DeliveringBody { inner: rx, state, id: reciever_id, generation })
}

struct DeliveringBody {
    inner: mpsc::Receiver<Bytes>,
    state: Arc<SessionState>,
    id: ReceiverId,
    generation: u64,
}
impl Drop for DeliveringBody {
    fn drop(&mut self) {
        // unregister, unless a reconnect has already replaced our entry
        let mut receivers = self.state.multicast().receivers.lock().unwrap();
        if receivers.get(&self.id).is_some_and(|(g, _)| *g == self.generation) {
            receivers.remove(&self.id);
        }
    }
}

impl Stream for DeliveringBody {
    type Item = Result<Bytes, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.poll_recv(cx).map(|item| item.map(Ok))
    }
}

pub fn parse_session(hex: &str) -> Result<SessionId, Error> {
    SessionId::from_hex(hex).map_err(|_| Error::BadSessionId)
}

#[derive(serde::Deserialize)]
pub struct TokenArgs {
    /// `relay_token` from `SessionCreated` / `SessionJoined`.
    token: String,
}

impl TokenArgs {
    fn parse(&self) -> Result<Token, Error> {
        Token::from_hex(&self.token).map_err(|_| Error::Unauthorized)
    }
}

/// Sender upload. `receiver_id` must be the session owner's id.
pub async fn post(
    Path((session_hex, receiver_hex)): Path<(String, String)>,
    Query(args): Query<TokenArgs>,
    State(state): State<Arc<AppState>>,
    body: Body,
) -> Result<(), Error> {
    let session_id = parse_session(&session_hex)?;
    let receiver_id = ReceiverId::from_hex(&receiver_hex).map_err(|_| Error::BadReceiverId)?;

    let session = state.get_session(session_id).await.ok_or(Error::SessionNotFound)?;
    if !session.authorize_relay(receiver_id, &args.parse()?, true).await {
        return Err(Error::Unauthorized);
    }

    run_session(session, body.into_data_stream()).await
}

/// Receiver download. `receiver_id` must be in the room, with its own token.
pub async fn get(
    Path((session_hex, receiver_hex)): Path<(String, String)>,
    Query(args): Query<TokenArgs>,
    State(state): State<Arc<AppState>>
) -> Result<Body, Error> {
    let session_id = parse_session(&session_hex)?;
    let receiver_id = ReceiverId::from_hex(&receiver_hex).map_err(|_| Error::BadReceiverId)?;
    let session = state.get_session(session_id).await.ok_or(Error::SessionNotFound)?;
    if !session.authorize_relay(receiver_id, &args.parse()?, false).await {
        return Err(Error::Unauthorized);
    }

    let body = add_receiver(session, receiver_id).await;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::room::PeerEntry;
    use bitmule_core::crypto::SessionMac;

    fn session(owner: ReceiverId) -> Arc<SessionState> {
        let (sink, _) = mpsc::channel(1);
        Arc::new(SessionState::new(owner, PeerEntry {
            sink,
            caps: bitmule_core::protocol::websocket::PeerCaps::RELAY,
            pub_key: bitmule_core::crypto::PublicKey([0; 32]),
            mac: SessionMac([0; 32]),
            reconnect_token: Token::random(),
            relay_token: Token::random(),
        }, [0; 32]))
    }

    #[tokio::test]
    async fn dropping_the_stream_unregisters_the_receiver() {
        let id = ReceiverId::random();
        let s = session(ReceiverId::random());
        let body = add_receiver(s.clone(), id).await;
        assert!(s.multicast().receivers.lock().unwrap().contains_key(&id));
        drop(body);
        assert!(s.multicast().receivers.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dropping_a_replaced_stream_keeps_the_new_one() {
        let id = ReceiverId::random();
        let s = session(ReceiverId::random());
        let old = add_receiver(s.clone(), id).await;
        let new = add_receiver(s.clone(), id).await;
        drop(old);
        assert!(s.multicast().receivers.lock().unwrap().contains_key(&id));
        drop(new);
        assert!(s.multicast().receivers.lock().unwrap().is_empty());
    }

    async fn next(body: &mut Body) -> Option<Bytes> {
        use http_body_util::BodyExt;
        tokio::time::timeout(std::time::Duration::from_millis(200), body.frame()).await.ok()?
            .and_then(|f| f.ok()?.into_data().ok())
    }

    fn stream(frames: Vec<Bytes>) -> BodyDataStream {
        Body::from_stream(futures::stream::iter(frames.into_iter().map(Ok::<_, Infallible>))).into_data_stream()
    }

    fn data_frame(payload: &[u8]) -> Bytes {
        let mut f = (payload.len() as u16).to_le_bytes().to_vec();
        f.push(F_DATA);
        f.extend_from_slice(payload);
        Bytes::from(f)
    }

    #[tokio::test]
    async fn sender_blocks_until_a_receiver_connects() {
        let s = session(ReceiverId::random());
        let run = tokio::spawn(run_session(s.clone(), stream(vec![data_frame(b"a")])));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!run.is_finished());

        let mut body = add_receiver(s.clone(), ReceiverId::random()).await;
        assert_eq!(&next(&mut body).await.unwrap()[3..], b"a");
        run.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn slow_receiver_drops_frames_fast_one_gets_all() {
        let s = session(ReceiverId::random());
        let mut fast = add_receiver(s.clone(), ReceiverId::random()).await;
        let _slow = add_receiver(s.clone(), ReceiverId::random()).await;

        let n = RECEIVER_QUEUE_DEPTH * 3;
        let frames = (0..n).map(|i| data_frame(&[i as u8])).collect();
        let run = tokio::spawn(run_session(s.clone(), stream(frames)));

        // `slow` never reads and fills up; `fast` keeps draining
        let mut got = 0;
        while let Some(f) = next(&mut fast).await {
            assert_eq!(f[3] as usize, got);
            got += 1;
        }
        assert_eq!(got, n);
        run.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn lone_slow_receiver_loses_nothing() {
        let s = session(ReceiverId::random());
        let mut body = add_receiver(s.clone(), ReceiverId::random()).await;
        let n = RECEIVER_QUEUE_DEPTH * 3;
        let frames = (0..n).map(|i| data_frame(&[i as u8])).collect();
        let run = tokio::spawn(run_session(s.clone(), stream(frames)));

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        for i in 0..n {
            assert_eq!(next(&mut body).await.unwrap()[3] as usize, i);
        }
        run.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn newer_sender_replaces_older() {
        let s = session(ReceiverId::random());
        let old = tokio::spawn(run_session(s.clone(), stream(vec![data_frame(b"x")])));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let new = tokio::spawn(run_session(s.clone(), stream(vec![])));
        assert!(matches!(old.await.unwrap(), Err(Error::Closed)));
        new.await.unwrap().unwrap();
    }
}
