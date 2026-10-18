//! Unpacking a received zip, held to the size the sender announced.

use std::{
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Result, bail, ensure};
use bitmule_core::protocol::websocket::{TransferManifest, TransferType};

/// How many bytes unpacking `manifest`'s zip may produce: what the sender
/// announced it holds. A sender that announces nothing (an older one, or the
/// browser) gets ten times the zip plus a GiB, which stored and ordinarily
/// compressed archives stay far below.
pub fn unpack_limit(manifest: &TransferManifest) -> u64 {
    match manifest.transfer_typ {
        TransferType::MultiFileZip { unpacked_size: Some(size), .. } => size,
        _ => manifest.transfer_size.saturating_mul(10).saturating_add(1 << 30),
    }
}

/// A directory in `into` called `name`, or `name (1)`, … that did not exist.
fn make_dir(into: &Path, name: &str) -> std::io::Result<PathBuf> {
    for n in 0.. {
        let dir = if n == 0 { into.join(name) } else { into.join(format!("{name} ({n})")) };
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

/// Unpack `zip_path` (stored, deflated or zstd entries) into a new directory
/// in `into`, named after the zip. Returns that directory.
///
/// The files may add up to `limit` bytes. That is checked against what the
/// entries declare before anything is written, and against what is actually
/// written while it is (a zip can lie about its sizes). If it goes over, or
/// anything else fails, the directory is removed again.
pub fn unpack_zip(zip_path: &Path, into: &Path, limit: u64) -> Result<PathBuf> {
    let mut archive = zip::ZipArchive::new(std::fs::File::open(zip_path)?)?;
    let mut declared = 0u64;
    for i in 0..archive.len() {
        declared = declared.saturating_add(archive.by_index_raw(i)?.size());
    }
    ensure!(declared <= limit, "the zip holds {declared} bytes, the sender announced {limit}");

    let stem = zip_path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "bundle".into());
    let dir = make_dir(into, &stem)?;
    let unpacked = (|| -> Result<()> {
        let mut budget = limit;
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            // `enclosed_name` refuses paths that would leave `dir`
            let Some(relative) = entry.enclosed_name() else { continue };
            let target = dir.join(relative);
            if entry.is_dir() {
                std::fs::create_dir_all(&target)?;
                continue;
            }
            if let Some(up) = target.parent() {
                std::fs::create_dir_all(up)?;
            }
            let written = std::io::copy(&mut (&mut entry).take(budget + 1), &mut std::fs::File::create(&target)?)?;
            if written > budget {
                bail!("the zip unpacks to more than the {limit} bytes the sender announced");
            }
            budget -= written;
        }
        Ok(())
    })();
    if let Err(e) = unpacked {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(e);
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zip_of(dir: &Path, files: &[(&str, usize)]) -> PathBuf {
        let path = dir.join("bundle.zip");
        let mut writer = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
        for (name, len) in files {
            writer.start_file(*name, zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated)).unwrap();
            writer.write_all(&vec![b'x'; *len]).unwrap();
        }
        writer.finish().unwrap();
        path
    }

    #[test]
    fn unpacks_within_the_announced_size() {
        let tmp = tempfile::tempdir().unwrap();
        let zip = zip_of(tmp.path(), &[("a/one.txt", 1000), ("two.txt", 500)]);
        let out = tmp.path().join("out");
        std::fs::create_dir(&out).unwrap();
        let dir = unpack_zip(&zip, &out, 1500).unwrap();
        assert_eq!(std::fs::metadata(dir.join("a/one.txt")).unwrap().len(), 1000);
        assert_eq!(std::fs::metadata(dir.join("two.txt")).unwrap().len(), 500);
    }

    #[test]
    fn a_zip_that_holds_more_than_announced_is_not_unpacked() {
        let tmp = tempfile::tempdir().unwrap();
        // compresses to a few dozen bytes
        let zip = zip_of(tmp.path(), &[("bomb.bin", 1 << 20)]);
        let out = tmp.path().join("out");
        std::fs::create_dir(&out).unwrap();
        assert!(unpack_zip(&zip, &out, 1000).is_err());
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0, "nothing left behind");
    }
}
