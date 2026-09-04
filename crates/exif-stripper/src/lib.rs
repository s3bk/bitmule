//! Browser-facing wasm-bindgen glue.
//!
//! `ExifStripTransformer` is a stateful transform step meant to be driven
//! by a JS `TransformStream`. It never buffers the whole file -- see
//! `core.rs` for the allocation story. The only per-call allocation is the
//! `Uint8Array` handed to `controller.enqueue()` for each output slice,
//! which is bounded by the input chunk size (typically 64 KiB from
//! `File.stream()`), not by file size.

mod core;

use core::Stripper;
use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use web_sys::TransformStreamDefaultController;

#[wasm_bindgen]
pub struct ExifStripTransformer {
    stripper: Stripper,
}

#[wasm_bindgen]
impl ExifStripTransformer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> ExifStripTransformer {
        ExifStripTransformer { stripper: Stripper::new() }
    }

    /// Called by the JS-side `TransformStream`'s `transform(chunk, controller)`
    /// for every chunk read from the source. `chunk` is a `Uint8Array`.
    #[wasm_bindgen]
    pub fn transform(
        &mut self,
        chunk: Uint8Array,
        controller: &TransformStreamDefaultController,
    ) -> Result<(), JsValue> {
        // One copy of the *chunk* (not the file) out of JS memory. Bounded
        // by the reader's chunk size, independent of file size.
        let bytes = chunk.to_vec();

        let mut err: Option<JsValue> = None;
        self.stripper.push(&bytes, &mut |out: &[u8]| {
            if err.is_some() || out.is_empty() {
                return;
            }
            // Exact-size allocation for the piece we're actually keeping --
            // no whole-file buffer, no re-allocation/growth.
            let arr = Uint8Array::new_with_length(out.len() as u32);
            arr.copy_from(out);
            if let Err(e) = controller.enqueue_with_chunk(&arr) {
                err = Some(e);
            }
        });
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Called once when the source is exhausted. Flushes any bytes the
    /// stripper is still holding (only relevant for truncated/malformed
    /// input -- well-formed JPEG/PNG streams are fully drained by `transform`).
    #[wasm_bindgen]
    pub fn flush(&mut self, controller: &TransformStreamDefaultController) -> Result<(), JsValue> {
        let mut err: Option<JsValue> = None;
        self.stripper.finish(&mut |out: &[u8]| {
            if err.is_some() || out.is_empty() {
                return;
            }
            let arr = Uint8Array::new_with_length(out.len() as u32);
            arr.copy_from(out);
            if let Err(e) = controller.enqueue_with_chunk(&arr) {
                err = Some(e);
            }
        });
        match err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl Default for ExifStripTransformer {
    fn default() -> Self {
        Self::new()
    }
}
