//! Compiles the one call Qt Quick does not offer to QML: setting the window
//! icon. `QQuickWindow` inherits `QWindow::setIcon`, but there is no QML
//! property for it (`ApplicationWindow.icon` does not exist), so a dozen
//! lines of C++ are the whole of it.
//!
//! Qt's headers are found the same way `qttypes` finds them: the
//! `QT_INCLUDE_PATH` environment variable, then `pkg-config`, then the
//! places distributions put Qt 6. If none of that works the build still
//! succeeds, without an icon, and says so.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/winicon.cpp");
    println!("cargo:rerun-if-changed=src/winicon_stub.c");
    println!("cargo:rerun-if-env-changed=QT_INCLUDE_PATH");

    match qt_include() {
        Some(include) => {
            cc::Build::new()
                .cpp(true)
                .file("src/winicon.cpp")
                .include(include)
                .flag_if_supported("-std=c++17")
                .compile("bitmule_winicon");
        }
        None => {
            println!(
                "cargo:warning=Qt 6 headers not found (set QT_INCLUDE_PATH); \
                 the window will have no icon"
            );
            cc::Build::new()
                .file("src/winicon_stub.c")
                .compile("bitmule_winicon");
        }
    }
}

fn qt_include() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("QT_INCLUDE_PATH") {
        if !p.is_empty() && Path::new(&p).join("QtGui").is_dir() {
            return Some(PathBuf::from(p));
        }
    }
    if let Ok(out) = Command::new("pkg-config")
        .args(["--cflags-only-I", "Qt6Gui"])
        .output()
    {
        if out.status.success() {
            let flags = String::from_utf8_lossy(&out.stdout).into_owned();
            if let Some(dir) = flags
                .split_whitespace()
                .filter_map(|f| f.strip_prefix("-I"))
                .find(|d| Path::new(d).join("QtGui").is_dir())
            {
                return Some(PathBuf::from(dir));
            }
        }
    }
    [
        "/usr/include/x86_64-linux-gnu/qt6",
        "/usr/include/qt6",
        "/usr/lib/qt6/include",
        "/usr/lib64/qt6/include",
        "/usr/local/include/qt6",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.join("QtGui").is_dir())
}
