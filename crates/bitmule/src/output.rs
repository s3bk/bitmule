//! Where received files land, and what happens when the name is taken.

use std::{
    fs::{File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

/// What to do when the file a transfer would write is already there.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum OnConflict {
    /// Ask. Without a terminal to ask on, this refuses.
    Ask,
    /// Replace the file.
    Overwrite,
    /// Leave the file, and fail the transfer.
    Reject,
    /// Keep the file, and write the new one as `name (1).ext`, `name (2).ext`, …
    #[default]
    Rename,
}

/// The answer to a question about a name that is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    Overwrite,
    Reject,
    Rename,
}

impl From<OnConflict> for Option<Choice> {
    fn from(policy: OnConflict) -> Self {
        match policy {
            OnConflict::Ask => None,
            OnConflict::Overwrite => Some(Choice::Overwrite),
            OnConflict::Reject => Some(Choice::Reject),
            OnConflict::Rename => Some(Choice::Rename),
        }
    }
}

fn create_new(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).write(true).create_new(true).open(path)
}

/// `name (n).ext` next to `path`.
fn numbered(path: &Path, n: u32) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, format!(".{ext}")),
        _ => (name.as_str(), String::new()),
    };
    path.with_file_name(format!("{stem} ({n}){ext}"))
}

/// Make the file `dest`, read and write. If it is taken, `policy` decides
/// (`ask` is called for [`OnConflict::Ask`]). Returns the path that was
/// made, which differs from `dest` when it was renamed.
pub fn open_new(dest: &Path, policy: OnConflict, ask: impl FnOnce(&Path) -> io::Result<Choice>) -> io::Result<(PathBuf, File)> {
    match create_new(dest) {
        Ok(file) => return Ok((dest.to_path_buf(), file)),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let choice = match Option::<Choice>::from(policy) {
        Some(choice) => choice,
        None => ask(dest)?,
    };
    match choice {
        Choice::Reject => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists already; not overwriting it", dest.display()),
        )),
        Choice::Overwrite => {
            let file = OpenOptions::new().read(true).write(true).truncate(true).open(dest)?;
            Ok((dest.to_path_buf(), file))
        }
        Choice::Rename => {
            for n in 1.. {
                let path = numbered(dest, n);
                match create_new(&path) {
                    Ok(file) => return Ok((path, file)),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
            }
            unreachable!()
        }
    }
}

/// Ask on the terminal what to do about `path`. Fails if there is no
/// terminal to ask on.
pub fn ask_on_terminal(path: &Path) -> io::Result<Choice> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists already, and there is no terminal to ask on: pass --on-conflict overwrite, reject or rename", path.display()),
        ));
    }
    // the transfer's other tasks keep running while we wait for the answer
    tokio::task::block_in_place(|| {
        let mut line = String::new();
        loop {
            eprint!("{} exists. [o]verwrite, [r]eject, re[n]ame? ", path.display());
            std::io::stderr().flush()?;
            line.clear();
            if std::io::stdin().lock().read_line(&mut line)? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no answer"));
            }
            match line.trim().to_ascii_lowercase().as_str() {
                "o" | "overwrite" => return Ok(Choice::Overwrite),
                "r" | "reject" => return Ok(Choice::Reject),
                "n" | "rename" => return Ok(Choice::Rename),
                _ => {}
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_free_name_is_taken_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = open_new(&dir.path().join("a.txt"), OnConflict::Reject, |_| unreachable!()).unwrap();
        assert_eq!(path, dir.path().join("a.txt"));
    }

    #[test]
    fn each_policy_does_what_it_says() {
        let dir = tempfile::tempdir().unwrap();
        let taken = dir.path().join("a.txt");
        std::fs::write(&taken, "mine").unwrap();

        let err = open_new(&taken, OnConflict::Reject, |_| unreachable!()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&taken).unwrap(), "mine");

        let (path, _) = open_new(&taken, OnConflict::Rename, |_| unreachable!()).unwrap();
        assert_eq!(path, dir.path().join("a (1).txt"));
        let (path, _) = open_new(&taken, OnConflict::Rename, |_| unreachable!()).unwrap();
        assert_eq!(path, dir.path().join("a (2).txt"));
        assert_eq!(std::fs::read_to_string(&taken).unwrap(), "mine");

        let (path, _) = open_new(&taken, OnConflict::Overwrite, |_| unreachable!()).unwrap();
        assert_eq!(path, taken);
        assert_eq!(std::fs::read_to_string(&taken).unwrap(), "");
    }

    #[test]
    fn ask_gets_the_final_say() {
        let dir = tempfile::tempdir().unwrap();
        let taken = dir.path().join("noext");
        std::fs::write(&taken, "mine").unwrap();
        let (path, _) = open_new(&taken, OnConflict::Ask, |p| {
            assert_eq!(p, taken);
            Ok(Choice::Rename)
        }).unwrap();
        assert_eq!(path, dir.path().join("noext (1)"));
        assert!(open_new(&taken, OnConflict::Ask, |_| Ok(Choice::Reject)).is_err());
    }
}
