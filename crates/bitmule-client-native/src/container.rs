//! On-the-fly bundling helpers for multi-file / directory transfers.
//!
//! The wire protocol carries a `container: Option<String>` flag on the
//! meta frame. Today the only container is `"zip-store"` — a level-0
//! (uncompressed) zip built on the sender's blocking pool and unpacked
//! on the receiver side. Level-0 is deliberate: bitmule already zstd's
//! the wire chunks downstream, so layering deflate here would waste CPU
//! on already-random ciphertext.
//!
//! Both helpers are async wrappers around `tokio::task::spawn_blocking`
//! since the `zip` crate is synchronous fs-bound.

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

/// Guard returned alongside the bundle path. Its `Drop` unlinks the
/// on-disk temp file, so the caller must keep it alive for as long as
/// the send task is reading from the bundle. Aliased so callers don't
/// need to depend on `tempfile` directly.
pub type ZipBundleGuard = tempfile::NamedTempFile;

/// Build a store-mode (level-0) zip bundle from `paths`. Returns the
/// `NamedTempFile` guard (kept alive by caller to survive the transfer;
/// `Drop` unlinks) and a display name for user output.
///
/// - Single file path: `<stem>.zip`, one entry.
/// - Single directory path: `<dirname>.zip`, walked recursively, entries
///   land under `<dirname>/...` inside the zip so the top-level container
///   name is preserved on extract.
/// - Multiple paths: `<first-stem>-and-N-more.zip`, each entry stored
///   under its basename (file) or `<dirname>/...` (dir).
///
/// Symlinks and other non-regular file types are skipped silently.
pub async fn build_zip_bundle(paths: &[PathBuf]) -> Result<(ZipBundleGuard, String)> {
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::CompressionMethod;

    if paths.is_empty() {
        return Err(anyhow!("no paths to bundle"));
    }

    let display_name = if paths.len() == 1 && paths[0].is_dir() {
        let base = paths[0].file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "bundle".to_string());
        format!("{base}.zip")
    } else if paths.len() == 1 {
        let stem = paths[0].file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "bundle".to_string());
        format!("{stem}.zip")
    } else {
        let stem = paths[0].file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "bundle".to_string());
        format!("{stem}-and-{}-more.zip", paths.len() - 1)
    };

    let owned_paths: Vec<PathBuf> = paths.to_vec();
    let tmp = tokio::task::spawn_blocking(move || -> Result<tempfile::NamedTempFile> {
        let tmp = tempfile::Builder::new()
            .prefix("bitmule-bundle-")
            .suffix(".zip")
            .tempfile()
            .context("create bundle tempfile")?;
        let file = tmp.reopen().context("reopen bundle tempfile")?;
        let mut zw = zip::ZipWriter::new(file);
        let opts: SimpleFileOptions = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .large_file(true);

        for p in &owned_paths {
            let md = std::fs::metadata(p)
                .with_context(|| format!("stat {}", p.display()))?;
            if md.is_file() {
                let name = p.file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .ok_or_else(|| anyhow!("path has no file name: {}", p.display()))?;
                zw.start_file(&name, opts)
                    .with_context(|| format!("zip start_file {name}"))?;
                let mut f = std::fs::File::open(p)
                    .with_context(|| format!("open {}", p.display()))?;
                std::io::copy(&mut f, &mut zw)
                    .with_context(|| format!("copy {} into zip", p.display()))?;
            } else if md.is_dir() {
                let root_name = p.file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .ok_or_else(|| anyhow!("dir path has no basename: {}", p.display()))?;
                for entry in walkdir::WalkDir::new(p).min_depth(1) {
                    let entry = entry.with_context(|| format!("walk {}", p.display()))?;
                    let rel = entry.path().strip_prefix(p)
                        .with_context(|| format!("strip_prefix {}", entry.path().display()))?;
                    let mut zip_name = std::path::PathBuf::from(&root_name);
                    zip_name.push(rel);
                    let zip_name_str = zip_name.to_string_lossy().replace('\\', "/");
                    let ft = entry.file_type();
                    if ft.is_dir() {
                        zw.add_directory(&zip_name_str, opts)
                            .with_context(|| format!("zip add_directory {zip_name_str}"))?;
                    } else if ft.is_file() {
                        zw.start_file(&zip_name_str, opts)
                            .with_context(|| format!("zip start_file {zip_name_str}"))?;
                        let mut f = std::fs::File::open(entry.path())
                            .with_context(|| format!("open {}", entry.path().display()))?;
                        std::io::copy(&mut f, &mut zw)
                            .with_context(|| format!("copy {} into zip", entry.path().display()))?;
                    }
                }
            } else {
                return Err(anyhow!("{} is neither a regular file nor a directory", p.display()));
            }
        }

        let mut inner = zw.finish().context("finalize zip central directory")?;
        inner.flush().context("flush zip file")?;
        Ok(tmp)
    }).await.context("zip build task join")??;

    Ok((tmp, display_name))
}

/// Sibling directory next to `zip_path`: `<parent>/<stem>/`, with a
/// `-1`, `-2`, … suffix if the target already exists. Returns a plain
/// `PathBuf`; caller creates it.
pub fn unpack_dir_for(zip_path: &Path) -> PathBuf {
    let parent = zip_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = zip_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "bundle".to_string());
    let mut candidate = parent.join(&stem);
    let mut n = 1u32;
    while candidate.exists() {
        candidate = parent.join(format!("{stem}-{n}"));
        n += 1;
    }
    candidate
}

/// Unpack an archive at `zip_path` into `dest`. Uses `enclosed_name()`
/// as the canonical zip-slip guard — entries whose path escapes `dest`
/// are skipped with a warning, not extracted. Returns the number of
/// FILE entries extracted (directories are counted separately and not
/// returned).
pub async fn unpack_zip_store(zip_path: &Path, dest: &Path) -> Result<usize> {
    let zip_path = zip_path.to_path_buf();
    let dest = dest.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<usize> {
        std::fs::create_dir_all(&dest)
            .with_context(|| format!("mkdir -p {}", dest.display()))?;
        let file = std::fs::File::open(&zip_path)
            .with_context(|| format!("open {}", zip_path.display()))?;
        let mut archive = zip::ZipArchive::new(file)
            .with_context(|| format!("read zip archive {}", zip_path.display()))?;
        let mut extracted: usize = 0;
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)
                .with_context(|| format!("zip entry #{i}"))?;
            let Some(rel) = entry.enclosed_name() else {
                tracing::warn!("skipping unsafe zip entry name: {:?}", entry.name());
                continue;
            };
            let out_path = dest.join(&rel);
            if entry.is_dir() {
                std::fs::create_dir_all(&out_path)
                    .with_context(|| format!("mkdir {}", out_path.display()))?;
            } else {
                if let Some(parent) = out_path.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("mkdir {}", parent.display()))?;
                }
                let mut out_file = std::fs::File::create(&out_path)
                    .with_context(|| format!("create {}", out_path.display()))?;
                std::io::copy(&mut entry, &mut out_file)
                    .with_context(|| format!("extract {}", out_path.display()))?;
                extracted += 1;
            }
        }
        Ok(extracted)
    }).await.context("zip unpack join")?
}
