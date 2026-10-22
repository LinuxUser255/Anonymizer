import org.gradle.api.tasks.testing.logging.TestExceptionFormat

// All versions pinned exactly; each checked on Maven Central on 2026-10-22:
//   org.jetbrains.kotlin:kotlin-gradle-plugin            2.4.21  (latest stable; 2.5.0 is Beta)
//   com.gradleup.shadow:shadow-gradle-plugin             9.6.1
//   net.portswigger.burp.extensions:montoya-api          2026.7
//   org.junit:junit-bom                                  6.1.3
plugins {
    kotlin("jvm") version "2.4.21"
    id("com.gradleup.shadow") version "9.6.1"
}

group = "com.anonymizer"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    // Burp provides the Montoya API at runtime; it is never bundled (its licence is not open source).
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")

    // No JSON library on purpose: the engine rewrites JSON in place with its own tokenizer.
    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
    jvmToolchain(21)
    compilerOptions {
        allWarningsAsErrors.set(false)
    }
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("failed", "skipped")
        exceptionFormat = TestExceptionFormat.FULL
        showStandardStreams = false
    }
}

tasks.shadowJar {
    // Produces build/libs/anonymizer-<version>-all.jar; Kotlin stdlib is bundled, Montoya is not.
    archiveBaseName.set("anonymizer")
    archiveClassifier.set("all")
    mergeServiceFiles()
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA")
    exclude("META-INF/versions/9/module-info.class", "module-info.class")
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
