# bitmule-android

Native Android shell for bitmule.  Kotlin + Compose UI; all
protocol logic (WebRTC negotiation, AEAD encrypt/decrypt, session
setup) lives in the shared `bitmule-mobile-ffi` Rust crate and is
called through UniFFI-generated Kotlin bindings.

## First build

```bash
# 1. Cross-compile the Rust .so per ABI.
cd ../crates/bitmule-mobile-ffi
cargo ndk -t aarch64-linux-android \
          -t armv7-linux-androideabi \
          -t x86_64-linux-android \
          -o ../../bitmule-android/app/src/main/jniLibs \
          build --release

# 2. Generate Kotlin bindings from the built .so.
cargo run --features=cli --bin uniffi-bindgen -- generate \
    --library ../../target/aarch64-linux-android/release/libbitmule_mobile_ffi.so \
    --language kotlin \
    --out-dir ../../bitmule-android/app/src/main/java

# 3. Build the APK.
cd ../../bitmule-android
./gradlew :app:assembleDebug
```

APK lands at `app/build/outputs/apk/debug/app-debug.apk`.

## Layout

- `app/src/main/AndroidManifest.xml` — permissions (INTERNET,
  ACCESS_NETWORK_STATE, CHANGE_WIFI_MULTICAST_STATE), intent
  filters (VIEW handler for `https://bitmule.qdat.net/#…`,
  ACTION_SEND handler for share-into-app), FileProvider config.
- `app/src/main/java/net/bitmule/MainActivity.kt` — single
  Activity; deep-link URL extraction for cold + warm starts.
- `app/src/main/java/net/bitmule/BitmuleApp.kt` — Compose UI;
  Send/Receive tabs, paste-URL flow, progress bar, FileProvider
  share intent for completed downloads.
- `app/src/main/jniLibs/` (gitignored) — Rust `.so` per ABI.
- `app/src/main/java/uniffi/` (gitignored) — UniFFI-generated
  Kotlin bindings.

## Milestones landed in this PR (M1 + partial M2)

- Rust FFI crate skeleton at `../crates/bitmule-mobile-ffi/`
- Gradle + Kotlin + Compose project scaffold
- Receive tab: paste-URL / VIEW-intent → fetch → progress bar →
  Share intent for completed file

## Not yet landed (follow-up)

- Send tab (M3): SAF file picker → sender orchestrator → QR + link
- Options + clipboard-watch + auto-download (M5)
- iOS shell (`../bitmule-ios/`) — same FFI, Swift + SwiftUI shell
- CI: matrix build for Android + iOS
- Signing config for release builds
