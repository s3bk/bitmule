// Top-level build file — plugin versions declared here, applied in app/build.gradle.kts.
//
// AGP bumped to 8.11.1: 8.7.2 internally used deprecated multi-string
// dependency notation for `lint-gradle`, which Gradle 10 will reject.
// 8.11.x internalizes lint-gradle with the single-string coordinate
// form. Kotlin 2.0.21 + compose plugin remain compatible (AGP 8.11
// supports Kotlin 2.0.x).
//
// If a build here surfaces "AGP requires Gradle >= 8.13" or similar,
// bump the Gradle wrapper (missing in-repo today) or your system
// gradle to 8.13+.
plugins {
    id("com.android.application") version "8.11.1" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}
