use std::path::PathBuf;

use bytes::Bytes;

use crate::protocol::websocket::TransferManifest;

pub struct TransferBuilder {
    files: Vec<FileEntry>
}
impl TransferBuilder {
    pub fn add_file(&mut self, storage: impl Into<Storage>, name: Option<PathBuf>) {
        self.files.push(FileEntry { name, storage: storage.into() });
    }
    pub async fn commit_async(self) -> (TransferManifest, Transfer) {
        // @kenna fill in
        // - generate bulk key
        // - hash all files
        unimplemented!()
    }
}

pub struct Transfer {
    files: Vec<FileEntry>,
    bulk_key: [u32; 8],
    commitment: [u8; 32]
}
pub struct FileEntry {
    name: Option<PathBuf>,
    storage: Storage,
}

pub struct TransferEntry {
    name: Option<PathBuf>,
    storage: Storage,
    hash: [u8; 32],
}

pub enum Storage {
    File(PathBuf),
    Bytes(Bytes),
}
impl From<PathBuf> for Storage {
    fn from(path: PathBuf) -> Self {
        Self::File(path)
    }
}
impl From<Bytes> for Storage {
    fn from(bytes: Bytes) -> Self {
        Storage::Bytes(bytes)
    }
}
