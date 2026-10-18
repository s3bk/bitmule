# bitmule for iOS

SwiftUI app on the Rust core (`crates/bitmule-mobile-ffi`, through UniFFI):
send and receive on one screen, a QR scanner (iOS's own detector), received
files in the Files app under "bitmule".

It is an [xtool](https://github.com/xtool-org/xtool) SwiftPM project, so it
builds from Linux (`xcode` here) as well as on a Mac, with no Xcode project.

```bash
xcode setup                # once: Darwin SDK, Apple ID
./build-rust.sh            # Rust core -> Libs/ios/libbitmule_mobile_ffi.a, Swift bindings
xcode dev build            # -> xtool/Bitmule.app
xcode dev                  # build, sign, install and launch on a connected device
```

`Sources/Bitmule/bitmule_mobile_ffi.swift` and
`Sources/bitmule_mobile_ffiFFI/include/` are generated (and checked in);
`./build-rust.sh` refreshes them after a change to the UDL.

The links: `https://bitmule.qdat.net/#…` is what the QR code and the share
sheet carry; `bitmule://host/#…` also opens the app. Opening plain https
links straight into the app (universal links) needs an Associated Domains
entitlement and a signed `apple-app-site-association` on the server; not set up.
