// swift-tools-version: 6.0

import PackageDescription

// Built with xtool (`xcode dev`), which is SwiftPM plus a Darwin SDK, so no
// Xcode project: the Rust core is a static library (build-rust.sh) that the
// app links, with the UniFFI header as a C module.
let package = Package(
    name: "Bitmule",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        // An xtool project contains exactly one library product: the app.
        .library(name: "Bitmule", targets: ["Bitmule"]),
    ],
    targets: [
        // UniFFI's C header for the Rust core
        .target(name: "bitmule_mobile_ffiFFI"),
        .target(
            name: "Bitmule",
            dependencies: ["bitmule_mobile_ffiFFI"],
            swiftSettings: [.swiftLanguageMode(.v5)],
            linkerSettings: [
                .unsafeFlags(["-L", Context.packageDirectory + "/Libs/ios"]),
                .linkedLibrary("bitmule_mobile_ffi"),
                .linkedLibrary("resolv"),
                .linkedFramework("Security"),
                .linkedFramework("CoreFoundation"),
                .linkedFramework("SystemConfiguration"),
            ]
        ),
    ]
)
