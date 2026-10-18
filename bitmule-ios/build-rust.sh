#!/usr/bin/env bash
# Builds the Rust core (bitmule-mobile-ffi) for iOS into Libs/ios and regenerates
# the Swift bindings, from Linux with the Darwin SDK that xtool installs
# (`xcode setup`), or on a Mac with Xcode.
#
#   ./build-rust.sh          # device (aarch64-apple-ios)
#   ./build-rust.sh sim      # simulator (aarch64-apple-ios-sim)
set -euo pipefail
cd "$(dirname "$0")"
TARGET=aarch64-apple-ios
SDKNAME=iPhoneOS
if [ "${1:-}" = sim ]; then TARGET=aarch64-apple-ios-sim; SDKNAME=iPhoneSimulator; fi
rustup target add "$TARGET"

if [ "$(uname -s)" != Darwin ]; then
    # no xcrun: point cc-rs at the SDK and a clang that can target Apple
    BUNDLE=${XTOOL_SDK:-$HOME/.config/swiftpm/swift-sdks/darwin.artifactbundle}
    export SDKROOT="$BUNDLE/Developer/Platforms/$SDKNAME.platform/Developer/SDKs/$SDKNAME.sdk"
    export IPHONEOS_DEPLOYMENT_TARGET=17.0
    TARGET_ENV=${TARGET//-/_}
    export "CC_$TARGET_ENV=${CLANG:-clang}"
    export "AR_$TARGET_ENV=${LLVM_AR:-$(command -v llvm-ar || command -v ar)}"
fi

# the staticlib only: the cdylib would need an Apple linker
(cd ../crates/bitmule-mobile-ffi &&
    CARGO_PROFILE_RELEASE_STRIP=symbols CARGO_PROFILE_RELEASE_DEBUG=false \
    cargo rustc --release --lib --crate-type staticlib --target "$TARGET")
mkdir -p Libs/ios
cp "../target/$TARGET/release/libbitmule_mobile_ffi.a" Libs/ios/

# Swift bindings + the C header come from the library's metadata (a host build is enough)
HOST_LIB=libbitmule_mobile_ffi.so
[ "$(uname -s)" = Darwin ] && HOST_LIB=libbitmule_mobile_ffi.dylib
(cd ../crates/bitmule-mobile-ffi &&
    cargo build -p bitmule-mobile-ffi &&
    cargo run -q --features=cli --bin uniffi-bindgen -- generate \
        --library "../../target/debug/$HOST_LIB" \
        --language swift --out-dir ../../bitmule-ios/.generated)
cp .generated/bitmule_mobile_ffi.swift Sources/Bitmule/
cp .generated/bitmule_mobile_ffiFFI.h Sources/bitmule_mobile_ffiFFI/include/
rm -rf .generated
echo "done: Libs/ios/libbitmule_mobile_ffi.a, Swift bindings updated"
