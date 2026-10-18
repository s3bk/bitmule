//! What travels over the WebRTC data channel, once it is open.
//!
//! The channel is reliable and ordered, and DTLS encrypts it, so the file's
//! bytes go over it as they are. The receiver asks for a range and the sender
//! answers with the range cut into pieces.
//!
//! `Get`:  `1 | start: u64 LE | end: u64 LE`
//! `Data`: `2 | offset: u64 LE | bytes`

use anyhow::{Result, bail, ensure};
use bytes::{BufMut, Bytes, BytesMut};

/// File bytes per `Data` message; small enough for every WebRTC stack.
pub const PIECE: usize = 16 * 1024;

/// The longest message: a `Data` header and a full piece.
pub const MESSAGE_MAX: usize = 9 + PIECE;

/// Buffers for `Data` messages. A message is made in one of these and goes
/// on as it is; the buffer returns to the pool once the channel has taken it.
pub type MessagePool = bitmule_buf::Pool<MESSAGE_MAX>;

pub fn message_pool() -> std::sync::Arc<MessagePool> {
    MessagePool::new(512, 128)
}

/// `Data { offset, bytes }` made in a pooled buffer; the piece is copied once, behind its header.
pub fn data_message(pool: &std::sync::Arc<MessagePool>, offset: u64, bytes: &[u8]) -> Bytes {
    let mut buf = pool.get();
    buf.push(2);
    buf.extend_from_slice(&offset.to_le_bytes());
    buf.extend_from_slice(bytes);
    buf.into_bytes()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    Get { start: u64, end: u64 },
    Data { offset: u64, bytes: Bytes },
}

impl Message {
    pub fn encode(&self) -> Bytes {
        let mut out = BytesMut::new();
        match self {
            Message::Get { start, end } => {
                out.put_u8(1);
                out.put_u64_le(*start);
                out.put_u64_le(*end);
            }
            Message::Data { offset, bytes } => {
                out.reserve(9 + bytes.len());
                out.put_u8(2);
                out.put_u64_le(*offset);
                out.put_slice(bytes);
            }
        }
        out.freeze()
    }

    pub fn decode(message: Bytes) -> Result<Self> {
        ensure!(message.len() >= 9, "short data channel message");
        let number = |at: usize| u64::from_le_bytes(message[at..at + 8].try_into().unwrap());
        match message[0] {
            1 => {
                ensure!(message.len() == 17, "bad Get message");
                Ok(Message::Get { start: number(1), end: number(9) })
            }
            2 => Ok(Message::Data { offset: number(1), bytes: message.slice(9..) }),
            tag => bail!("unknown data channel message {tag}"),
        }
    }
}

/// `Data` as it arrives in pieces (one per SCTP chunk): the offset, and the
/// bytes after the 9 byte header, still in the memory they arrived in.
pub fn data_parts(mut parts: Vec<Bytes>) -> Result<(u64, Vec<Bytes>)> {
    use bytes::Buf;
    // the first chunk holds the header unless it is tiny; then join them
    if parts.first().is_none_or(|first| first.len() < 9) {
        let joined: Bytes = parts.iter().flat_map(|p| p.iter().copied()).collect::<Vec<u8>>().into();
        return match Message::decode(joined)? {
            Message::Data { offset, bytes } => Ok((offset, vec![bytes])),
            Message::Get { .. } => bail!("a Get where data was expected"),
        };
    }
    ensure!(parts[0][0] == 2, "not a data message");
    let offset = u64::from_le_bytes(parts[0][1..9].try_into().unwrap());
    parts[0].advance(9);
    parts.retain(|p| !p.is_empty());
    Ok((offset, parts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pooled_data_messages_match_encode() {
        let pool = message_pool();
        for (offset, piece) in [(0u64, &b""[..]), (77, &b"hello"[..]), (1 << 40, &[7u8; PIECE][..])] {
            let pooled = data_message(&pool, offset, piece);
            let plain = Message::Data { offset, bytes: Bytes::copy_from_slice(piece) }.encode();
            assert_eq!(pooled, plain);
        }
        let idle = pool.idle();
        drop(data_message(&pool, 1, b"x"));
        assert!(pool.idle() >= idle);
    }

    #[test]
    fn messages_survive_the_wire() {
        for m in [
            Message::Get { start: 3, end: 1 << 40 },
            Message::Data { offset: 77, bytes: Bytes::from_static(b"hello") },
            Message::Data { offset: 0, bytes: Bytes::new() },
        ] {
            assert_eq!(Message::decode(m.encode()).unwrap(), m);
        }
        assert!(Message::decode(Bytes::from_static(b"\x09abcdefgh")).is_err());
        assert!(Message::decode(Bytes::from_static(b"\x01")).is_err());
    }
}
