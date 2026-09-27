use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{File, FileSystemFileHandle, Blob};
use js_sys::{ArrayBuffer, Uint8Array, Promise};
use futures_lite::io::AsyncRead;

use crate::Error;

/// Reads a `FileSystemFileHandle` in `chunk_size` byte chunks,
/// calling `callback` with each `&[u8]` slice.
///
/// # Errors
/// Returns a `JsValue` error if any JS/Web API call fails.
pub async fn read_file_in_chunks<F>(
    handle: &FileSystemFileHandle,
    chunk_size: u64,
    mut callback: F,
) -> Result<(), JsValue>
where
    F: FnMut(&[u8]),
{
    // 1. Get a `File` object from the handle
    let file: web_sys::File = JsFuture::from(handle.get_file())
        .await?
        .dyn_into::<web_sys::File>()?;

    let total_size = file.size() as u64; // f64 → u64
    let mut offset: u64 = 0;

    while offset < total_size {
        let end = (offset + chunk_size).min(total_size);

        // 2. Slice the File (a Blob) — slice(start, end) in bytes
        let blob: Blob = file
            .slice_with_f64_and_f64(offset as f64, end as f64)?
            .into();

        // 3. Read the blob slice as an ArrayBuffer
        let array_buffer: ArrayBuffer =
            JsFuture::from(blob.array_buffer())
                .await?
                .dyn_into::<ArrayBuffer>()?;

        // 4. View the buffer as a Uint8Array and copy into a Vec<u8>
        let uint8_array = Uint8Array::new(&array_buffer);
        let mut chunk = vec![0u8; uint8_array.length() as usize];
        uint8_array.copy_to(&mut chunk);

        // 5. Hand the slice to the caller
        callback(&chunk);

        offset = end;
    }

    Ok(())
}

pub async fn open_read(handle: &FileSystemFileHandle) -> Result<impl AsyncRead, Error> {
    let file: File = JsFuture::from(handle.get_file())
        .await?
        .dyn_into()?;

    // File derefs to Blob, so `.stream()` is available directly.
    let raw: web_sys::ReadableStream = file.stream();

    let stream = wasm_streams::ReadableStream::from_raw(raw);
    Ok(stream.into_async_read())
}
