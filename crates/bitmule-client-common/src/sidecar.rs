//! Where an installed client finds the helper programs it ships with.
//!
//! Two helpers travel with every native build (what they are and why they are
//! separate binaries: `docs/sidecars.md`):
//!
//! * `ffmpeg` — an LGPL build carrying SVT-AV1. The video encoder: every
//!   uploaded video is converted on the sender's machine, before encryption,
//!   into something a browser can stream.
//! * `bitmule-linearize` — the PDF linearizer. Puts page 1 and everything it
//!   reads at the front of the file, so a receiver can show a page before the
//!   rest has arrived.
//!
//! Neither is a library we link: ffmpeg under LGPL stays a separate program
//! that we exec, and the linearizer is its own crate in the pdf_render tree.
//! What the client needs is therefore only *where they are*, decided in one
//! place so all front ends agree.
//!
//! Search order, first hit wins:
//!
//! 1. `$BITMULE_TOOLS` — a directory, for development and for tests.
//! 2. next to the executable: `tools/<name>`, then `<name>`.
//! 3. macOS `.app`: `../Resources/tools/<name>`, then `../Resources/<name>`.
//! 4. `$PATH`.
//!
//! A bundled copy wins over `$PATH` on purpose: a system ffmpeg without
//! `libsvtav1` would otherwise shadow ours and silently drop video to a worse
//! encoder.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// A helper program that ships with the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tool {
    /// ffmpeg, LGPL, with `libsvtav1`.
    Ffmpeg,
    /// `bitmule-linearize`.
    Linearize,
}

impl Tool {
    /// Both, in the order a client is likely to need them.
    pub const ALL: [Tool; 2] = [Tool::Ffmpeg, Tool::Linearize];

    /// The file name as it appears in a bundle.
    pub fn file_name(self) -> &'static str {
        match self {
            Tool::Ffmpeg => {
                if cfg!(windows) {
                    "ffmpeg.exe"
                } else {
                    "ffmpeg"
                }
            }
            Tool::Linearize => {
                if cfg!(windows) {
                    "bitmule-linearize.exe"
                } else {
                    "bitmule-linearize"
                }
            }
        }
    }

    /// A short phrase for messages, e.g. "the video encoder".
    pub fn role(self) -> &'static str {
        match self {
            Tool::Ffmpeg => "the video encoder (ffmpeg with SVT-AV1)",
            Tool::Linearize => "the PDF linearizer",
        }
    }
}

/// Why a helper could not be found.
#[derive(Clone, Debug)]
pub struct Missing {
    pub tool: Tool,
    /// The directories and files that were looked at, in order.
    pub searched: Vec<PathBuf>,
}

impl std::fmt::Display for Missing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}) is not installed: looked in {}",
            self.tool.file_name(),
            self.tool.role(),
            self.searched
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl std::error::Error for Missing {}

/// The places a lookup consults, taken from the environment once.
#[derive(Clone, Debug, Default)]
pub struct Locator {
    /// `$BITMULE_TOOLS`.
    tools_dir: Option<PathBuf>,
    /// The directory holding the running executable.
    exe_dir: Option<PathBuf>,
    /// `$PATH`, split.
    path_dirs: Vec<PathBuf>,
}

impl Locator {
    /// Read the environment.
    pub fn from_env() -> Self {
        let exe = std::env::current_exe().ok();
        Self::with(
            exe.as_deref(),
            std::env::var_os("BITMULE_TOOLS"),
            std::env::var_os("PATH"),
        )
    }

    /// Build one from the three things a lookup depends on. Split out so a
    /// test can hand over a directory tree instead of changing the process
    /// environment.
    pub fn with(
        exe: Option<&Path>,
        tools_dir: Option<OsString>,
        path_var: Option<OsString>,
    ) -> Self {
        let path_dirs = path_var
            .map(|p| std::env::split_paths(&p).collect())
            .unwrap_or_default();
        Self {
            tools_dir: tools_dir.map(PathBuf::from),
            exe_dir: exe.and_then(|e| e.parent().map(Path::to_path_buf)),
            path_dirs,
        }
    }

    /// Every candidate path for `tool`, in the order it is tried. Useful for
    /// an error message and for a test that wants to see the whole ladder.
    pub fn candidates(&self, tool: Tool) -> Vec<PathBuf> {
        let name = tool.file_name();
        let mut out = Vec::new();
        if let Some(dir) = &self.tools_dir {
            out.push(dir.join(name));
        }
        if let Some(dir) = &self.exe_dir {
            out.push(dir.join("tools").join(name));
            out.push(dir.join(name));
            // A macOS .app: Contents/MacOS/bitmule -> Contents/Resources/.
            if let Some(contents) = dir.parent() {
                out.push(contents.join("Resources").join("tools").join(name));
                out.push(contents.join("Resources").join(name));
            }
        }
        for dir in &self.path_dirs {
            out.push(dir.join(name));
        }
        out
    }

    /// The first candidate that exists.
    pub fn find(&self, tool: Tool) -> Option<PathBuf> {
        self.candidates(tool)
            .into_iter()
            .find(|p| p.is_file())
    }

    /// Like [`find`](Self::find), but says what it looked at when it fails.
    pub fn require(&self, tool: Tool) -> Result<PathBuf, Missing> {
        match self.find(tool) {
            Some(p) => Ok(p),
            None => Err(Missing {
                tool,
                searched: self.candidates(tool),
            }),
        }
    }

    /// Both helpers, found or not — what `bitmule version` prints.
    pub fn report(&self) -> Vec<(Tool, Option<PathBuf>)> {
        Tool::ALL.iter().map(|&t| (t, self.find(t))).collect()
    }
}

/// Find `tool` using the current environment.
pub fn find(tool: Tool) -> Option<PathBuf> {
    Locator::from_env().find(tool)
}

/// Find `tool` or explain where it was expected.
pub fn require(tool: Tool) -> Result<PathBuf, Missing> {
    Locator::from_env().require(tool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// An empty directory tree that cleans up after itself.
    struct Tree(PathBuf);

    impl Tree {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "bitmule-sidecar-{tag}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Tree(p)
        }
        fn dir(&self, rel: &str) -> PathBuf {
            let p = self.0.join(rel);
            fs::create_dir_all(&p).unwrap();
            p
        }
        fn file(&self, rel: &str) -> PathBuf {
            let p = self.0.join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&p, b"").unwrap();
            p
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_bundle_next_to_the_executable_wins_over_path() {
        let t = Tree::new("bundle");
        let exe = t.file("app/bin/bitmule");
        let bundled = t.file(&format!("app/bin/tools/{}", Tool::Ffmpeg.file_name()));
        // A different ffmpeg sits on $PATH; the bundled one must win.
        let elsewhere = t.dir("usr/bin");
        let on_path = elsewhere.join(Tool::Ffmpeg.file_name());
        fs::write(&on_path, b"").unwrap();

        let loc = Locator::with(Some(&exe), None, Some(elsewhere.clone().into_os_string()));
        assert_eq!(loc.find(Tool::Ffmpeg), Some(bundled));
    }

    #[test]
    fn a_macos_app_finds_its_resources() {
        let t = Tree::new("app");
        let exe = t.file("Bitmule.app/Contents/MacOS/bitmule");
        let res = t.file(&format!(
            "Bitmule.app/Contents/Resources/{}",
            Tool::Linearize.file_name()
        ));
        let loc = Locator::with(Some(&exe), None, None);
        assert_eq!(loc.find(Tool::Linearize), Some(res));
    }

    #[test]
    fn the_tools_override_comes_first() {
        let t = Tree::new("override");
        let exe = t.file("app/bitmule");
        t.file(&format!("app/tools/{}", Tool::Linearize.file_name()));
        let dev_dir = t.dir("dev");
        let dev = t.file(&format!("dev/{}", Tool::Linearize.file_name()));
        let loc = Locator::with(Some(&exe), Some(dev_dir.into_os_string()), None);
        assert_eq!(loc.find(Tool::Linearize), Some(dev));
    }

    #[test]
    fn a_missing_tool_says_where_it_looked() {
        let t = Tree::new("missing");
        let exe = t.file("app/bitmule");
        let loc = Locator::with(Some(&exe), None, None);
        let err = loc.require(Tool::Ffmpeg).unwrap_err();
        assert!(err.to_string().contains("tools/ffmpeg"), "{err}");
        // Both spots next to the executable, plus the two .app ones; no PATH.
        assert_eq!(err.searched.len(), 4, "{:?}", err.searched);
    }
}
