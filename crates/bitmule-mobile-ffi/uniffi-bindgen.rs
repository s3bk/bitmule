// Thin wrapper so the cross-compile pipeline can generate Kotlin
// (Android) and Swift (iOS) bindings from the built `.so`/`.a`
// artifact rather than from source. Invoked by the Gradle / Xcode
// build steps described in the crate README.

fn main() {
    uniffi::uniffi_bindgen_main()
}
