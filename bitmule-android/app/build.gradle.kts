plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "net.bitmule"
    compileSdk = 35

    defaultConfig {
        applicationId = "net.bitmule"
        minSdk = 33          // WebRTC + Compose comfortable floor.
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        // NDK ABI filter: match the ABIs cargo-ndk emits into
        // src/main/jniLibs. Update both places in lockstep.
        ndk {
            abiFilters += listOf(
                "arm64-v8a",
                "armeabi-v7a",
                "x86_64",
            )
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions { jvmTarget = "17" }

    buildFeatures {
        compose = true
    }

    // Rust .so files land here from `cargo ndk build --release
    // -p bitmule-mobile-ffi -o app/src/main/jniLibs` — see the
    // FFI crate README for the exact recipe.
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")
}

dependencies {
    // Compose BOM keeps everything version-aligned.
    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")

    // UniFFI's Kotlin runtime. Version must match the uniffi Rust
    // crate version in bitmule-mobile-ffi/Cargo.toml (currently 0.28).
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
