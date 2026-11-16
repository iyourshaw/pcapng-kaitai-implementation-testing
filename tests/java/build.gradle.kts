// Builds the Java code that ksc generates from pcapng.ksy (in generated/, made
// by scripts/compile.py) and decodes every sample with it.

plugins {
    java
}

val repoRoot = rootDir.parentFile.parentFile

java {
    toolchain {
        // Temurin 25 only. gradle.properties turns off JDK auto-download, so
        // this never resolves to GraalVM or another vendor's JDK.
        languageVersion = JavaLanguageVersion.of(25)
        vendor = JvmVendorSpec.ADOPTIUM
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("io.kaitai:kaitai-struct-runtime:0.11")

    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("com.fasterxml.jackson.core:jackson-databind:2.23.0")
    // JSON comparison with path-level diffs, as Hamcrest matchers (JsonUnit uses
    // the Jackson 2 above to serialize the summaries).
    testImplementation("net.javacrumbs.json-unit:json-unit:6.4.0")
    testImplementation("org.hamcrest:hamcrest:3.0")
}

sourceSets {
    main {
        java.srcDir("generated")
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    // Report the generated code's warnings. this-escape is left out: every
    // ksc-generated class calls _read() from its constructor.
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Xlint:-serial", "-Xlint:-this-escape", "-Xmaxwarns", "10000"))
}

tasks.test {
    useJUnitPlatform()
    systemProperty("samples.dir", repoRoot.resolve("samples").absolutePath)
    systemProperty("expected.dir", repoRoot.resolve("tests/expected").absolutePath)
    // Rerun when the samples or golden files change.
    inputs.dir(repoRoot.resolve("samples")).withPropertyName("samples")
    inputs.dir(repoRoot.resolve("tests/expected")).withPropertyName("expected")
    testLogging {
        events("failed", "skipped")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
