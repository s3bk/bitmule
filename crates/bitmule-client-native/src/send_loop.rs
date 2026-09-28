use std::{collections::HashSet, io::SeekFrom};

use bitmule_core::{ChunkBitmap, ChunkHasher, ChunkSize, ReceiverId};
use bitmule_crypto::{BulkKey, ShareKey, ShareLink};
use bitvec::{order::Lsb0, view::BitView};
use bytes::{BufMut, Bytes, BytesMut};
use futures::Stream;
use indexmap::IndexMap;
use tokio::{fs::File, io::{AsyncBufRead, AsyncReadExt, AsyncSeek, AsyncSeekExt}, pin, spawn, sync::mpsc, task::JoinHandle};
use tokio_stream::wrappers::ReceiverStream;

use crate::commit_reader;

struct ShareHandle {
    handle: JoinHandle<()>,
    link: ShareLink,
}

async fn send_file(file: impl AsyncBufRead + AsyncSeek) -> Result<ShareHandle, anyhow::Error> {
    let share_key = ShareKey::random();
    let bulk_key = BulkKey::random();
    let session_hex = share_key.session_id_hex();
    pin!(file);
    let signature = commit_reader(&mut file, &bulk_key).await?;
    let link = ShareLink::new(share_key.clone(), signature);

    //let transport = Transport::Relay | Transport::WebRtc;
    //let session = create_session(session_id, transport);        // CreateSession { session_id, transport } -> Server

    let handle = tokio::spawn(async move {

    });

    Ok(ShareHandle { handle, link })
}

enum SendRelayCmd {
    AddReceiver {
        id: ReceiverId,
        wants: ChunkBitmap
    },
    RemoveReceiver {
        id: ReceiverId
    }
}
async fn send_relay_loop(mut cmd_rx: mpsc::Receiver<SendRelayCmd>, mut file: File, chunk_size: ChunkSize) -> Result<impl Stream<Item = Bytes>, anyhow::Error> {
    let (bodx_tx, body_rx) = mpsc::channel(10);

    let file_len = file.metadata().await?.len();
    let frame_size = (chunk_size.size() as usize).min(0xf000);
    let num_chunks = chunk_size.num_chunks(file_len);

    spawn(async move {
        use bitmule_core::protocol::relay_frame::*;

        let mut missing = ChunkBitmap::new();
        let mut bitmaps: IndexMap<ReceiverId, ChunkBitmap> = IndexMap::new();
        let mut nothing_to_send = true;
        let mut bitmaps_added = false;
        let mut bitmaps_modified = false;
        let mut receivers_removed = HashSet::new();
        let mut chunk_idx = 0;
        let mut selection_mask: Vec<u8> = vec![];
        let mut prev_selection_mask: Vec<u8> = vec![];

        'main: loop {
            let cmd = if nothing_to_send && !bitmaps_modified {
                match cmd_rx.recv().await {
                    Some(c) => Some(c),
                    None => break,
                }
            } else {
                match cmd_rx.try_recv() {
                    Ok(c) => Some(c),
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                    Err(mpsc::error::TryRecvError::Empty) => None,
                }
            };

            match cmd {
                Some(SendRelayCmd::AddReceiver { id, wants }) => {
                    bitmaps.insert(id, wants);
                    bitmaps_added = true;
                    bitmaps_modified = true;
                    continue;
                }
                Some(SendRelayCmd::RemoveReceiver { id }) => {
                    if let Some(wants) = bitmaps.get_mut(&id) {
                        wants.bits.clear();
                        bitmaps_modified = true;
                        receivers_removed.insert(id);
                    }
                    continue;
                }
                None => {}
            }

            // if this point has been reached, there are no pending commands
            // update bitmaps if needed
            if bitmaps_modified {
                bitmaps_modified = false;
                missing.bits.clear();
                for needed in bitmaps.values() {
                    missing.bits |= &needed.bits;
                }
                nothing_to_send = missing.bits.is_empty();
                if nothing_to_send {
                    // nothing to do, reset current chunk_idx and await instructions
                    chunk_idx = 0;
                    continue;
                }
            }

            // find next chunk that needs sending
            match missing.bits.range(chunk_idx..).next() {
                Some(idx) => chunk_idx = idx,
                None => {
                    chunk_idx = 0;
                    continue;
                }
            }
            if chunk_idx >= num_chunks {
                break; // should never happen
            }

            if bitmaps_added || receivers_removed.len() > 8 || selection_mask.len() == 0 {
                bitmaps_added = false;
                // update reciever table
                // first apply any pending removes
                for id in receivers_removed.drain() {
                    bitmaps.swap_remove(&id);
                }
                let payload_size = bitmaps.len() * size_of::<ReceiverId>();
                let mut frame = BytesMut::with_capacity(1 + FRAME_SIZE_BYTES + payload_size);
                frame.put_u16_le(payload_size as u16);
                frame.put_u8(F_ROUTING_UPDATE);
                for id in bitmaps.keys() {
                    frame.extend_from_slice(&id.0);
                }
                if let Err(_) = bodx_tx.send(frame.freeze()).await {
                    break 'main;
                }

                selection_mask.resize((bitmaps.len() + 7) / 8, 0);
            }

            // compute selection mask
            selection_mask.fill(0);
            for (mut bit, needed) in selection_mask.view_bits_mut::<Lsb0>().into_iter().zip(bitmaps.values()) {
                *bit = needed.has(chunk_idx);
            }
            if selection_mask != prev_selection_mask {
                let payload_size = selection_mask.len();
                let mut frame = BytesMut::with_capacity(1 + FRAME_SIZE_BYTES + payload_size);
                frame.put_u16_le(payload_size as u16);
                frame.put_u8(F_SELECTION_UPDATE);
                frame.extend_from_slice(&selection_mask);
                if let Err(_) = bodx_tx.send(frame.freeze()).await {
                    break 'main;
                }

                prev_selection_mask.clear();
                prev_selection_mask.extend_from_slice(&selection_mask);
            }

            let start_pos = chunk_idx as u64 * chunk_size.size();
            let this_chunk_size = (file_len - start_pos).min(chunk_size.size()) as usize;
            if let Err(_) = file.seek(SeekFrom::Start(start_pos)).await {
                break 'main;
            }
            let mut hasher = ChunkHasher::new(chunk_idx);
            let mut bytes_sent = 0;
            while bytes_sent < this_chunk_size {
                let payload_len = (file_len - start_pos - bytes_sent as u64).min(frame_size as u64) as usize;
                let is_first = bytes_sent == 0;
                let is_last = bytes_sent + payload_len == this_chunk_size;
                let extra = is_first as usize * 8 + is_last as usize * 8;
                let mut frame = BytesMut::zeroed(1 + FRAME_SIZE_BYTES + payload_len + extra);
                frame[..FRAME_SIZE_BYTES].copy_from_slice(&(payload_len as u16).to_le_bytes());
                frame[FRAME_SIZE_BYTES] = F_DATA;
                let payload_start = FRAME_SIZE_BYTES+1 + is_first as usize * 8;
                if is_first {
                    frame[FRAME_SIZE_BYTES+1..FRAME_SIZE_BYTES+5].copy_from_slice(&chunk_idx.to_le_bytes());
                    frame[FRAME_SIZE_BYTES+5..FRAME_SIZE_BYTES+9].copy_from_slice(&this_chunk_size.to_le_bytes());
                }

                let payload = &mut frame[payload_start..payload_start+payload_len];
                if let Err(e) = file.read_exact(payload).await {
                    tracing::error!({e=%e}, "reading file");
                    break 'main;
                }
                hasher.add_frame(&*payload);

                if is_last {
                    let digest = hasher.digest();
                    frame[payload_start+payload_len..].copy_from_slice(&digest.to_le_bytes());
                }

                if let Err(_) = bodx_tx.send(frame.freeze()).await {
                    break 'main;
                }
                bytes_sent += payload_len;
            }

            chunk_idx += 1;
        }
    });

    Ok(ReceiverStream::new(body_rx))
}

/*
 * a sequence of chunks is sent.
 * each chunk is transfered via multiple data frames

  each chunk begins with
  4 LE bytes chunk index
  4 LE bytes chunk size

  followed by the contents of the chunk

  8 LE bytes chunk hash
 */
