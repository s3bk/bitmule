use bitmule_core::{ChunkBitmap, Manifest, ReceiverId};

async fn recv_loop() {

}

async fn get_data_relay() {

}
async fn get_data_webrtc(manifest: &Manifest) {

}
async fn recv_link() {
    //let bulk = get_bulk_key();
    //let data_relay = get_data_relay();
}

struct Session {

}

enum RtcSenderToReceiver {
    Chunk {
        idx: u32,
        data: Vec<u8>,
        hash: u64,
    }
}
enum RtcReceiverToSender {
    // moves communication on the sender from websocket to webrtc
    // sender will cancel remaining tansfers over relay and move them over to the websocket
    Hello { id: ReceiverId },
    RequestChunks {
        chunks: ChunkBitmap
    },
    Complete
}
