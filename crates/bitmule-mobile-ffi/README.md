# bitmule-mobile-ffi

Shared UniFFI-exported surface for the Android (Kotlin) and iOS
(Swift) bitmule shells. Wraps `bitmule-client-native` +
`bitmule-crypto` behind a stable UDL so the two mobile UI trees
never depend on the internal crate boundaries.

## Cross-compile (Android)

```bash
# One-time: install cargo-ndk + Android NDK rustup targets.
cargo install cargo-ndk
rustup target add aarch64-linux-android armv7-linux-androideabi \
                  x86_64-linux-android i686-linux-android

# Build the .so per ABI + drop into the app's jniLibs.
cargo ndk -t aarch64-linux-android \
          -t armv7-linux-androideabi \
          -t x86_64-linux-android \
          -o ../../bitmule-android/app/src/main/jniLibs \
          build --release -p bitmule-mobile-ffi

# Generate Kotlin bindings from the .so.
cargo run --features=cli --bin uniffi-bindgen -- generate \
    --library ../../target/aarch64-linux-android/release/libbitmule_mobile_ffi.so \
    --language kotlin \
    --out-dir ../../bitmule-android/app/src/main/java
```

## Cross-compile (iOS)

```bash
# One-time: install rustup targets.
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

# Build a universal xcframework via cbindgen + xcodebuild -create-xcframework.
# Full recipe lives at ../../bitmule-ios/build-xcframework.sh.
```

## FFI surface

The UDL at `src/bitmule_mobile_ffi.udl` is the authoritative
definition. Current v0.1.0 exports:

- `parse_share_url(url) -> ParsedShareUrl` — pure-function URL
  splitter for paste-and-preview flows.
- `recv_file(url, out_dir, progress) -> RecvOutcome` (async) —
  full receive path: negotiate → stream → decrypt → verify → return
  final on-disk path.
- Typed error variants (`InvalidUrl`, `Network`, `Transport`,
  `Verify`, `Io`, `Unknown`) so the shell gets pattern-matchable
  catches, not stringly-typed exceptions.

Bump `ffi_version()` on any UDL change so the mobile shell can fail
fast on `.so`-vs-bindings mismatch after an OTA update.

## Threading

`recv_file` runs its own tokio runtime; the shell can await/suspend
from any coroutine or dispatch queue. Progress callbacks may fire
from tokio worker threads — the shell MUST marshal to the UI thread
before touching Compose/SwiftUI state.
