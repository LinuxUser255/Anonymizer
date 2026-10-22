// Toolchain auto-provisioning: the engine targets JVM 21 (CLAUDE.md). If no JDK 21 is installed,
// this convention plugin lets Gradle download one into ~/.gradle/jdks on first build.
// Version checked on plugins.gradle.org (1.0.0, 2025-05-19).
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "anonymizer"
