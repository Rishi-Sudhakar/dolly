plugins {
    kotlin("jvm") version "2.0.21"
}

repositories {
    mavenCentral()
}

dependencies {
    // Test-only. The shipped core uses nothing beyond the JDK / Android platform.
    testImplementation(kotlin("test"))
    testImplementation("org.json:json:20240303")
}

kotlin {
    jvmToolchain(17)
}

tasks.test {
    useJUnit()
    // The conformance vectors live outside this project; re-run whenever they change.
    inputs.files(fileTree("../test-vectors"))
    testLogging {
        showStackTraces = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
