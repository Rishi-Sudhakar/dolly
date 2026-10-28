plugins {
    kotlin("jvm") version "2.0.21"
    application
}

application {
    mainClass.set("com.dolly.cli.MainKt")
    applicationName = "dolly"
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

// `gradle run` needs the terminal's stdin to be interactive: gradle -q --console=plain run
tasks.named<JavaExec>("run") {
    standardInput = System.`in`
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
