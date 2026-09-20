use std::path::PathBuf;

use bitmule_crypto::{commit_reader, BulkKey, CommitmentHasher};
use bytes::Bytes;

use crate::protocol::websocket::{TransferManifest, TransferType};

pub struct TransferBuilder {
    files: Vec<FileEntry>,
    /// Force MultiFileZip framing even for a single file. Off by default —
    /// single-file transfers ship the raw bytes to avoid an unnecessary
    /// zip container.
    force_zip: bool,
}

impl TransferBuilder {
    pub fn new() -> Self {
        Self { files: Vec::new(), force_zip: false }
    }

    pub fn add_file(&mut self, storage: impl Into<Storage>, name: Option<PathBuf>) {
        self.files.push(FileEntry { name, storage: storage.into() });
    }

    /// Force MultiFileZip transfer_typ even if only one file was added.
    /// Useful when the receiver needs the zip envelope regardless (e.g.
    /// consistent extract path in the UI).
    pub fn force_multi_file_zip(&mut self) {
        self.force_zip = true;
    }

    pub async fn commit_async(self) -> anyhow::Result<(TransferManifest, Transfer)> {
        let bulk_key = BulkKey::random();
        let use_zip = self.force_zip || self.files.len() != 1;

        let (transfer_typ, transfer_size, commitment) = if use_zip {
            let (zip_size, zip_commit) = zip_and_commit(&self.files, &bulk_key).await?;
            (
                TransferType::MultiFileZip { outer_compression: None },
                zip_size,
                zip_commit,
            )
        } else {
            // len == 1 && !force_zip
            let entry = &self.files[0];
            let (size, commit) = single_file_commit(&entry.storage, &bulk_key).await?;
            (
                TransferType::SingleFile { compression: None },
                size,
                commit,
            )
        };

        let manifest = TransferManifest {
            transfer_typ,
            block_size: 1024 * 1024, // 1 MiB relay chunks — matches BulkKey chunk-nonce assumption
            transfer_size,
            bulk_key: bulk_key.clone(),
        };
        let transfer = Transfer {
            files: self.files,
            bulk_key,
            commitment,
        };
        Ok((manifest, transfer))
    }
}

impl Default for TransferBuilder {
    fn default() -> Self { Self::new() }
}

pub struct Transfer {
    files: Vec<FileEntry>,
    bulk_key: BulkKey,
    commitment: [u8; 32],
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

async fn single_file_commit(storage: &Storage, bulk_key: &BulkKey) -> anyhow::Result<(u64, [u8; 32])> {
    match storage {
        Storage::File(path) => {
            let f = tokio::fs::File::open(path).await?;
            let size = f.metadata().await?.len();
            let mut r = f;
            let commit = commit_reader(&mut r, bulk_key).await?;
            Ok((size, commit))
        }
        Storage::Bytes(b) => {
            let size = b.len() as u64;
            let mut hasher = CommitmentHasher::new();
            hasher.update(b);
            Ok((size, hasher.finalize(bulk_key)))
        }
    }
}

/// Build a zip of every file in `files` via `async_zip` into a temp file,
/// then stream that temp file through the CommitmentHasher. Returns
/// (zip_size, commitment).
///
/// Design notes:
/// - `async_zip` (0.0.19) has a wasm-compatible core, so this path stays
///   usable in the browser once we wire it there.
/// - Compression = Stored: AEAD downstream defeats it anyway.
/// - Entry name = `entry.name` file_name, or `file_<idx>` fallback.
///
/// TODO(wasm): tempfile is native-only. For the browser build the temp
/// staging should live on OPFS via StorageManager.getDirectory() →
/// getFileHandle({create:true}) → FileSystemSyncAccessHandle inside a
/// web worker (sync access handle is worker-scope only per MDN). Design
/// the abstraction when we wire the wasm side, not before.
async fn zip_and_commit(
    files: &[FileEntry],
    bulk_key: &BulkKey,
) -> anyhow::Result<(u64, [u8; 32])> {
    use async_zip::base::write::ZipFileWriter;
    use async_zip::{Compression, ZipEntryBuilder};
    use futures_lite::io::AsyncWriteExt as _;
    use tokio::io::AsyncReadExt;
    use tokio_util::compat::TokioAsyncWriteCompatExt;

    let tmp = tempfile::NamedTempFile::new()?;
    let tmp_path = tmp.path().to_path_buf();
    let out = tokio::fs::File::create(&tmp_path).await?;
    let mut writer = ZipFileWriter::new(out.compat_write());

    for (idx, entry) in files.iter().enumerate() {
        let name = entry
            .name
            .as_ref()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
            .unwrap_or_else(|| format!("file_{idx}"));
        let builder = ZipEntryBuilder::new(name.into(), Compression::Stored);

        match &entry.storage {
            Storage::File(path) => {
                // Stream file → zip entry in 64 KiB chunks; whole file never
                // held in memory.
                let mut src = tokio::fs::File::open(path).await?;
                let mut stream = writer.write_entry_stream(builder).await?;
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = src.read(&mut buf).await?;
                    if n == 0 { break; }
                    stream.write_all(&buf[..n]).await?;
                }
                stream.close().await?;
            }
            Storage::Bytes(b) => {
                writer.write_entry_whole(builder, b).await?;
            }
        }
    }
    writer.close().await?;

    let zip_size = tokio::fs::metadata(&tmp_path).await?.len();

    // Stream the built zip through CommitmentHasher.
    let mut f = tokio::fs::File::open(tmp.path()).await?;
    let commit = commit_reader(&mut f, bulk_key).await?;
    drop(tmp);

    Ok((zip_size, commit))
}
