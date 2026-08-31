import java.util.jar.JarFile

dependencies {
    api(project(":mcace-sdk"))
    implementation(project(":mcace-protocol"))
    testImplementation(project(":mcace-client-common"))
}

// The client needs only the observation value types below.  Keep the normal `jar`
// unchanged for every server module, and publish a separate, closed artifact for
// Fabric packaging.  An explicit class allowlist makes a new core dependency fail
// the final client-artifact closure tests instead of silently shipping server code.
val clientSafeCoreClassEntries = setOf(
    "com/ellan/mcace/core/disposition/ArtifactObservation.class",
    "com/ellan/mcace/core/disposition/ArtifactType.class",
    "com/ellan/mcace/core/disposition/Confidence.class",
    "com/ellan/mcace/core/disposition/ObservationOrigin.class",
)

val clientSafeJar = tasks.register<org.gradle.api.tasks.bundling.Jar>("clientSafeJar") {
    group = "build"
    description = "Builds the explicit client-safe subset of mcace-core."
    archiveClassifier.set("client-safe")
    dependsOn(tasks.named("classes"))
    from(sourceSets.main.get().output) {
        include(clientSafeCoreClassEntries)
    }
    includeEmptyDirs = false
    duplicatesStrategy = DuplicatesStrategy.FAIL

    // Keep the verification action configuration-cache serializable: do not capture
    // Kotlin DSL script locals in the task action closure.
    doLast {
        val expectedCoreClasses = setOf(
            "com/ellan/mcace/core/disposition/ArtifactObservation.class",
            "com/ellan/mcace/core/disposition/ArtifactType.class",
            "com/ellan/mcace/core/disposition/Confidence.class",
            "com/ellan/mcace/core/disposition/ObservationOrigin.class",
        )
        val artifact = archiveFile.get().asFile
        val actualCoreClasses = JarFile(artifact).use { jar ->
            jar.entries().asSequence()
                .filter { entry ->
                    !entry.isDirectory && entry.name.startsWith("com/ellan/mcace/core/") &&
                        entry.name.endsWith(".class")
                }
                .map { it.name }
                .toSet()
        }
        check(actualCoreClasses == expectedCoreClasses) {
            "client-safe core classes differ from the reviewed allowlist; " +
                "expected=$expectedCoreClasses actual=$actualCoreClasses"
        }
    }
}

configurations.create("clientSafeElements") {
    description = "Consumable client-safe mcace-core artifact; never use for server runtime."
    isCanBeConsumed = true
    isCanBeResolved = false
    outgoing.artifact(clientSafeJar)
}
