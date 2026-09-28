//!
//! Frame formats
//!
//! ROUTING
//! - 2 bytes data length n (LE)
//! - 1 byte with value 3
//! - n = 16 * num_ids bytes containing LE encoded ReceiverId
//!
//! Selection update
//! - 2 bytes data length n (LE)
//! - 1 byte with value 2
//! - n = ceil(n_indices / 8) bytes with the bits for the corresponding reciever indices set to 1
//!
//! Data
//! - 2 bytes payload length n (LE)
//! - 1 byte with value 1
//! - n bytes payload


use std::{borrow::Cow, collections::HashMap, convert::Infallible, io, pin::Pin, sync::Arc, task::{Context, Poll}};

use axum::{body::{Body, BodyDataStream}, extract::{Path, State}, http::{HeaderMap, StatusCode}, response::IntoResponse};
use bitvec::{order::Lsb0, view::BitView};
use bytes::{Buf, Bytes, BytesMut};
use futures::{TryStreamExt};
use futures_util::{Stream, StreamExt};
use tokio::{pin, sync::{AcquireError, Mutex, Semaphore, mpsc::{self, error::TrySendError}}};
use tokio_util::{codec::{Decoder, FramedRead}, io::StreamReader};
use itertools::izip;
use bitmule_core::{ReceiverId, SessionId, pow, protocol::relay_frame::*};

use crate::{AppState, state::SessionState};


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
        src.advance(1 + FRAME_SIZE_BYTES);

        let payload = src.split_to(frame_length).freeze();
        Ok(Some((frame_type, payload)))
    }
}

#[derive(Debug)]
pub enum Error {
    BadSessionId,
    BadReceiverId,
    SessionNotFound,
    Io(io::Error),
    InvalidFrameType(u8),
    SelectionLength { expected: usize, found: usize },
    Closed,
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<AcquireError> for Error {
    fn from(_: AcquireError) -> Self {
        Error::Closed
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        let (status, body): (StatusCode, Cow<str>) = match self {
            Error::Io(e) => (StatusCode::BAD_REQUEST, "Io Error".into()),
            Error::InvalidFrameType(t) => (StatusCode::BAD_REQUEST, format!("invalid frame type: {t}").into()),
            Error::SelectionLength { expected, found } => (
                StatusCode::BAD_REQUEST,
                format!("selection length mismatch: expected {expected}, found {found}").into(),
            ),
            Error::Closed => (StatusCode::SERVICE_UNAVAILABLE, "session closed".into()),
            Error::BadSessionId => (StatusCode::BAD_REQUEST, "Invalid Session ID".into()),
            Error::BadReceiverId => (StatusCode::BAD_REQUEST, "Invalid Receiver ID".into()),
            Error::SessionNotFound => (StatusCode::NOT_FOUND, "Session ID not found".into()),
        };
        (status, body).into_response()
    }
}

struct Dest {
    tx: mpsc::Sender<Bytes>,
}

pub struct MulticastSession {
    receivers: Mutex<HashMap<ReceiverId, mpsc::Sender<Bytes>>>,
    semaphore: Semaphore,
}
impl Default for MulticastSession {
    fn default() -> Self {
        MulticastSession { receivers: Default::default(), semaphore: Semaphore::new(0) }
    }
}

pub async fn run_session(state: Arc<SessionState>, stream: BodyDataStream) -> Result<(), Error> {
    let session = state.multicast();
    let reader = StreamReader::new(stream.map_err(io::Error::other));
    let stream = FramedRead::new(reader, FrameDecoder);
    pin!(stream);

    let mut routing_table: Vec<Option<Dest>> = vec![];
    let mut selection_bits = vec![];

    while let Some(next) = stream.next().await {
        let (frame_type, data) = next?;

        match frame_type {
            F_DATA => {
                let bitset = || selection_bits.view_bits::<Lsb0>().iter().by_vals();

                let n_required = izip!(bitset(), routing_table.iter_mut()).filter(|&(include, ref dest)| include && dest.is_some()).count();
                let mut permits = session.semaphore.acquire_many(n_required as u32).await?;

                for (include, dest_opt) in izip!(bitset(), routing_table.iter_mut()) {
                    if !include {
                        continue;
                    }
                    let Some(ref dest) = *dest_opt else { continue };

                    match dest.tx.try_send(data.clone()) {
                        Ok(()) => {
                            permits.split(1).unwrap().forget();
                        },
                        Err(TrySendError::Closed(_)) => {
                            *dest_opt = None;
                        }
                        Err(TrySendError::Full(_)) => {}
                    }
                }
            }
            F_SELECTION_UPDATE => {
                if selection_bits.len() != data.len() {
                    return Err(Error::SelectionLength { expected: selection_bits.len(), found: data.len() });
                }
                selection_bits.copy_from_slice(&*data);
            }
            F_ROUTING_UPDATE => {
                let n_old = routing_table.len();
                routing_table.clear();
                let receivers = session.receivers.lock().await;
                routing_table.extend(data.chunks_exact(size_of::<ReceiverId>()).map(|chunk| {
                    let id = ReceiverId(chunk.try_into().unwrap());
                    let tx = receivers.get(&id)?.clone();
                    Some(Dest { tx })
                }));

                let n_new = routing_table.len();
                if n_old < n_new {
                    session.semaphore.add_permits(n_new - n_old);
                } else if n_new < n_old {
                    session.semaphore.acquire_many((n_old - n_new) as u32).await?.forget();
                }
                selection_bits.resize((n_new + 7) / 8, 0);
            }
            _ => return Err(Error::InvalidFrameType(frame_type))
        }
    }

    Ok(())
}

pub async fn add_receiver(state: Arc<SessionState>, reciever_id: ReceiverId) -> Body {
    let (tx, rx) = mpsc::channel(1);
    state.multicast().receivers.lock().await.insert(reciever_id, tx);

    let stream = DeliveringBody { inner: rx, state };
    Body::from_stream(stream)
}

struct DeliveringBody {
    inner: mpsc::Receiver<Bytes>,
    state: Arc<SessionState>,
}
impl Drop for DeliveringBody {
    fn drop(&mut self) {
        // Buffered items that will never fire their delivery-side add_permits.
        // Return them all now.
        let leftover = self.inner.len();
        self.state.multicast().semaphore.add_permits(leftover);
    }
}

impl Stream for DeliveringBody {
    type Item = Result<Bytes, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(data)) => {
                self.state.multicast().semaphore.add_permits(1);
                Poll::Ready(Some(Result::<_, Infallible>::Ok(data)))
            }
            Poll::Ready(None) => Poll::Ready(None)
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.inner.is_closed() {
            let used_capacity = self.inner.max_capacity() - self.inner.capacity();
            (self.inner.len(), Some(used_capacity))
        } else {
            (self.inner.len(), None)
        }
    }
}

pub fn parse_session(hex: &str) -> Result<SessionId, Error> {
    SessionId::from_hex(hex).map_err(|_| Error::BadSessionId)
}

pub async fn post(
    Path((session_hex, receiver_hex)): Path<(String, String)>,
    State(state): State<AppState>,
    body: Body,
) -> Result<(), Error> {
    let session_id = parse_session(&session_hex)?;
    let receiver_id = ReceiverId::from_hex(&receiver_hex).map_err(|e| Error::BadReceiverId)?;

    let session = state.get_session(session_id).await.ok_or(Error::SessionNotFound)?;

    run_session(session, body.into_data_stream()).await
}
pub async fn get(
    Path((session_hex, receiver_hex)): Path<(String, String)>,
    State(state): State<AppState>
) -> Result<Body, Error> {
    let session_id = parse_session(&session_hex)?;
    let receiver_id = ReceiverId::from_hex(&receiver_hex).map_err(|e| Error::BadReceiverId)?;
    let session = state.get_session(session_id).await.ok_or(Error::SessionNotFound)?;

    let body = add_receiver(session, receiver_id).await;
    Ok(body)
}
