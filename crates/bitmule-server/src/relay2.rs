use std::{collections::{HashMap}, convert::Infallible, io, pin::Pin, sync::Arc, task::{Context, Poll}};

use axum::body::{Body, BodyDataStream};
use biter::{Biter};
use bytes::{Buf, Bytes, BytesMut};
use futures::{TryStreamExt};
use futures_util::{Stream, StreamExt};
use tokio::{pin, sync::{AcquireError, Mutex, Semaphore, mpsc::{self, error::TrySendError}}};
use tokio_util::{codec::{Decoder, FramedRead}, io::StreamReader};
use itertools::izip;

#[derive(PartialEq, Eq, Hash)]
pub struct ReceiverId(pub u128);


#[repr(u8)]
enum FrameType {
    Chunk = 1,
    SelectionUpdate = 2,
    RoutingUpdate = 3,
}
const F_CHUNK: u8 = FrameType::Chunk as u8;
const F_SELECTION_UPDATE: u8 = FrameType::SelectionUpdate as u8;
const F_ROUTING_UPDATE: u8 = FrameType::RoutingUpdate as u8;


struct FrameDecoder;

impl Decoder for FrameDecoder {
    type Item = (u8, Bytes);
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.remaining() < 3 { return Ok(None); }  // type(1) + len(2)

        let frame_length = u16::from_le_bytes(src[0..2].try_into().unwrap()) as usize;
        let frame_type = src[2];

        if src.remaining() < 3 + frame_length as usize {
            return Ok(None);
        }
        src.advance(3);

        let payload = src.split_to(frame_length).freeze();
        Ok(Some((frame_type, payload)))
    }
}

#[derive(Debug)]
pub enum Error {
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

struct Dest {
    is_closed: bool,
    tx: mpsc::Sender<Bytes>,
}

pub struct MulticastSession {
    receivers: Mutex<HashMap<ReceiverId, mpsc::Sender<Bytes>>>,
    semaphore: Semaphore,
}

pub async fn run_session(session: Arc<MulticastSession>, stream: BodyDataStream) -> Result<(), Error> {
    let reader = StreamReader::new(stream.map_err(io::Error::other));
    let stream = FramedRead::new(reader, FrameDecoder);
    pin!(stream);

    let mut routing_table: Vec<Dest> = vec![];
    let mut selection_bits = vec![];

    while let Some(next) = stream.next().await {
        let (frame_type, data) = next?;

        match frame_type {
            F_CHUNK => {
                let bitset = || Biter::from(&*selection_bits);

                let n_required = izip!(bitset(), routing_table.iter_mut()).filter(|&(include, ref dest)| include && !dest.is_closed).count();
                let mut permits = session.semaphore.acquire_many(n_required as u32).await?;

                for (include, dest) in izip!(bitset(), routing_table.iter_mut()) {
                    if !include || dest.is_closed {
                        continue;
                    }

                    match dest.tx.try_send(data.clone()) {
                        Ok(()) => {
                            permits.split(1).unwrap().forget();
                        },
                        Err(TrySendError::Closed(_)) => {
                            dest.is_closed = true;
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
                routing_table.extend(data.chunks_exact(size_of::<ReceiverId>()).flat_map(|chunk| {
                    let id = ReceiverId(u128::from_le_bytes(chunk.try_into().unwrap()));
                    let tx = receivers.get(&id)?.clone();
                    Some(Dest {
                        is_closed: false, tx
                    })
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

pub async fn add_receiver(session: &Arc<MulticastSession>, reciever_id: ReceiverId) -> Body {
    let (tx, rx) = mpsc::channel(1);
    session.receivers.lock().await.insert(reciever_id, tx);

    let session = session.clone();
    let stream = DeliveringBody { inner: rx, session: session.clone() };
    Body::from_stream(stream)
}

struct DeliveringBody {
    inner: mpsc::Receiver<Bytes>,
    session: Arc<MulticastSession>,
}
impl Drop for DeliveringBody {
    fn drop(&mut self) {
        // Buffered items that will never fire their delivery-side add_permits.
        // Return them all now.
        let leftover = self.inner.len();
        self.session.semaphore.add_permits(leftover);
    }
}

impl Stream for DeliveringBody {
    type Item = Result<Bytes, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(data)) => {
                self.session.semaphore.add_permits(1);
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
