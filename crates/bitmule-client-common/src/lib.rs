use std::io;

use async_zip::error::ZipError;

pub mod transfer;
pub mod fountain;
#[cfg(not(target_arch = "wasm32"))]
pub mod blockio;
#[cfg(target_arch = "wasm32")]
pub mod web;
pub mod fs;

#[cfg(target_arch = "wasm32")]
pub mod opfs;

#[derive(Debug)]
pub enum Error {
    #[cfg(target_arch = "wasm32")]
    Js(wasm_bindgen::JsValue),

    Io(std::io::Error),

    Zip(ZipError),

    Anyhow(anyhow::Error),
}

#[cfg(target_arch = "wasm32")]
impl From<wasm_bindgen::JsValue> for Error {
    fn from(v: wasm_bindgen::JsValue) -> Self {
        Error::Js(v)
    }
}
impl From<ZipError> for Error {
    fn from(v: ZipError) -> Self {
        Error::Zip(v)
    }
}
impl From<anyhow::Error> for Error {
    fn from(v: anyhow::Error) -> Self {
        Error::Anyhow(v)
    }
}
impl From<io::Error> for Error {
    fn from(v: io::Error) -> Self {
        Error::Io(v)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(target_arch = "wasm32")]
            Error::Js(e) => write!(f, "{e:?}"),

            Error::Io(e) => write!(f, "{e:?}"),

            Error::Zip(e) => write!(f, "{e:?}"),

            Error::Anyhow(e) => write!(f, "{e:?}"),
        }
    }
}

impl std::error::Error for Error {}
