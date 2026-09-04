fn main() {
    uniffi::generate_scaffolding("src/bitmule_mobile_ffi.udl")
        .expect("uniffi scaffolding failed");
}
