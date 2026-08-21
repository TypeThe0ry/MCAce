import groovy.json.JsonSlurper
import java.io.File
import java.security.MessageDigest
import java.util.HexFormat
import java.util.jar.JarFile

plugins {
    id("net.fabricmc.fabric-loom-remap") version "1.14.10"
}

repositories {
    maven("https://maven.fabricmc.net/") {
        name = "fabric"
    }
}

dependencies {
    minecraft("com.mojang:minecraft:1.21.11")
    mappings("net.fabricmc:yarn:1.21.11+build.6:v2")
    modImplementation("net.fabricmc:fabric-loader:0.19.3")
    modImplementation("net.fabricmc.fabric-api:fabric-api:0.141.6+1.21.11")
    implementation(project(":mcace-client-common"))
    include(project(":mcace-client-common"))
    // Pin these to their JAR variants: Loom can otherwise select core's empty resources variant.
    include(project(mapOf("path" to ":mcace-core", "configuration" to "runtimeElements")))
    include(project(mapOf("path" to ":mcace-sdk", "configuration" to "runtimeElements")))
    include(project(":mcace-protocol"))
    include("com.google.protobuf:protobuf-java:4.32.1")
}

val mcaceClientBuildId = providers.gradleProperty("mcaceClientBuildId")
    .orElse(providers.gradleProperty("mcaceSourceCommit")
        .map { commit -> "fabric-1.21.11-$commit" })
    .getOrElse("fabric-phase2-dev")
val mcaceVersion = version.toString()
val smokeArtifactMode = providers.gradleProperty("mcaceSmokeArtifactMode")
    .map { configured ->
        require(configured == "true" || configured == "false") {
            "mcaceSmokeArtifactMode must be exactly true or false"
        }
        configured.toBooleanStrict()
    }
    .orElse(false)
val smokeArtifactModeEnabled = smokeArtifactMode.get()
val smokeExpectedArtifactSha256 = providers.gradleProperty("mcaceSmokeExpectedArtifactSha256")
val smokeRunToken = providers.gradleProperty("mcaceSmokeRunToken")

if (smokeArtifactModeEnabled) {
    require(Regex("(?:platform-smoke-[0-9]{8}T[0-9]{9}Z|[0-9a-f]{32})")
            .matches(mcaceClientBuildId)) {
        "artifact-mode mcaceClientBuildId must be a platform-smoke timestamp ID or 32 lowercase hex characters"
    }
    smokeExpectedArtifactSha256.orNull?.let { expected ->
        require(Regex("[0-9a-f]{64}").matches(expected)) {
            "mcaceSmokeExpectedArtifactSha256 must be exactly 64 lowercase hex characters"
        }
    }
    smokeRunToken.orNull?.let { token ->
        require(Regex("[0-9a-f]{32}").matches(token)) {
            "mcaceSmokeRunToken must be exactly 32 lowercase hex characters"
        }
    }
}

fun sha256(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().buffered().use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            digest.update(buffer, 0, read)
        }
    }
    return HexFormat.of().formatHex(digest.digest())
}

fun isMcaceFabricMetadata(input: java.io.InputStream): Boolean {
    val metadata = JsonSlurper().parse(input) as? Map<*, *> ?: return false
    return metadata["id"] == "mcace"
}

fun containsConflictingMcaceFabricOrigin(candidate: File): Boolean {
    val entrypointClass = "com/ellan/mcace/fabric/MCAceFabricClient.class"
    if (candidate.isDirectory) {
        if (candidate.resolve(entrypointClass).isFile) return true
        val metadata = candidate.resolve("fabric.mod.json")
        return metadata.isFile && metadata.inputStream().buffered().use(::isMcaceFabricMetadata)
    }
    if (!candidate.isFile || !candidate.extension.equals("jar", ignoreCase = true)) return false
    return JarFile(candidate).use { jar ->
        if (jar.getJarEntry(entrypointClass) != null) return@use true
        val metadata = jar.getJarEntry("fabric.mod.json") ?: return@use false
        jar.getInputStream(metadata).buffered().use(::isMcaceFabricMetadata)
    }
}

tasks.processResources {
    val resourceProperties = mapOf(
        "mcace_version" to mcaceVersion,
        "mcace_client_build_id" to mcaceClientBuildId
    )
    inputs.properties(resourceProperties)
    filesMatching("fabric.mod.json") {
        expand(resourceProperties)
    }
}

val deployableRemapJar = tasks.named<org.gradle.api.tasks.bundling.AbstractArchiveTask>("remapJar")

if (smokeArtifactModeEnabled) {
    // Loom normally exposes this project's main source-set outputs as the development mod.
    // In artifact mode every configured mod is first emptied, then the one MCAce mod is
    // bound exclusively to the final production remap JAR.
    loom.mods.configureEach {
        modFiles.setFrom(emptyList<Any>())
    }
    loom.mods.maybeCreate("mcace").apply {
        modFiles.setFrom(deployableRemapJar)
    }
}

val mcaceMainOutputRoots = providers.provider {
    rootProject.subprojects.flatMap { mcaceProject ->
        mcaceProject.extensions
            .getByType<org.gradle.api.tasks.SourceSetContainer>()
            .getByName(org.gradle.api.tasks.SourceSet.MAIN_SOURCE_SET_NAME)
            .output.files
    }.map { it.canonicalFile.toPath() }.toSet()
}

val runClientTask = tasks.named<org.gradle.api.tasks.JavaExec>("runClient")

if (smokeArtifactModeEnabled) {
    runClientTask.configure {
        dependsOn(deployableRemapJar)
        val developmentClasspath = classpath
        classpath = developmentClasspath.filter { candidate ->
            val candidatePath = candidate.canonicalFile.toPath()
            mcaceMainOutputRoots.get().none { outputRoot ->
                candidatePath.startsWith(outputRoot) || outputRoot.startsWith(candidatePath)
            }
        }
        doFirst {
            val expectedArtifactSha256 = smokeExpectedArtifactSha256.orNull
                ?: throw GradleException(
                    "artifact-mode runClient requires -PmcaceSmokeExpectedArtifactSha256=<64 lowercase hex>")
            val runToken = smokeRunToken.orNull
                ?: throw GradleException(
                    "artifact-mode runClient requires -PmcaceSmokeRunToken=<32 lowercase hex>")
            systemProperty("mcace.platform-smoke.expected-artifact-sha256", expectedArtifactSha256)
            systemProperty("mcace.smoke.run-token", runToken)
        }
    }
}

val verifySmokeArtifactMode = tasks.register("verifySmokeArtifactMode") {
    group = "verification"
    description = "Proves that Fabric smoke startup can only load MCAce from the final remap JAR."
    dependsOn(deployableRemapJar)
    inputs.property("mcaceSmokeArtifactMode", smokeArtifactMode)
    inputs.property("mcaceClientBuildId", mcaceClientBuildId)
    inputs.file(deployableRemapJar.flatMap { it.archiveFile })

    doLast {
        check(smokeArtifactMode.get()) {
            "verifySmokeArtifactMode requires -PmcaceSmokeArtifactMode=true"
        }
        val artifact = deployableRemapJar.get().archiveFile.get().asFile.canonicalFile
        check(artifact.isFile && artifact.length() > 0L) {
            "artifact-mode Fabric remap JAR is missing or empty"
        }
        val expectedArtifactSha256 = smokeExpectedArtifactSha256.orNull
            ?: throw GradleException(
                "verifySmokeArtifactMode requires -PmcaceSmokeExpectedArtifactSha256=<64 lowercase hex>")
        check(sha256(artifact) == expectedArtifactSha256) {
            "artifact-mode Fabric remap JAR does not match the operator-started run hash"
        }
        check(smokeRunToken.isPresent) {
            "verifySmokeArtifactMode requires -PmcaceSmokeRunToken=<32 lowercase hex>"
        }

        val nonEmptyMods = loom.mods.mapNotNull { mod ->
            val files = mod.modFiles.files.map { it.canonicalFile }.toSet()
            if (files.isEmpty()) null else mod.name to files
        }
        check(nonEmptyMods == listOf("mcace" to setOf(artifact))) {
            "artifact-mode Loom mods must contain only mcace -> final remap JAR"
        }
        val forbiddenRoots = mcaceMainOutputRoots.get()
        val leakedOutputs = runClientTask.get().classpath.files.map { it.canonicalFile.toPath() }
            .filter { candidate ->
                forbiddenRoots.any { outputRoot ->
                    candidate.startsWith(outputRoot) || outputRoot.startsWith(candidate)
                }
            }
        check(leakedOutputs.isEmpty()) {
            "artifact-mode runClient classpath contains MCAce main source outputs"
        }
        val conflictingOrigins = runClientTask.get().classpath.files
            .map { it.canonicalFile }
            .filter { it != artifact && containsConflictingMcaceFabricOrigin(it) }
        check(conflictingOrigins.isEmpty()) {
            "artifact-mode runClient classpath contains another MCAce Fabric origin: " +
                conflictingOrigins.joinToString()
        }

        val metadata = JarFile(artifact).use { jar ->
            val entry = checkNotNull(jar.getJarEntry("fabric.mod.json")) {
                "artifact-mode Fabric remap JAR is missing fabric.mod.json"
            }
            jar.getInputStream(entry).bufferedReader(Charsets.UTF_8).use { it.readText() }
        }
        val expectedBuildIdentity = Regex(
            "\\\"mcace:client_build_id\\\"\\s*:\\s*\\\"${Regex.escape(mcaceClientBuildId)}\\\""
        )
        check(expectedBuildIdentity.findAll(metadata).count() == 1) {
            "artifact-mode Fabric remap JAR does not contain the exact requested build ID"
        }
        check(!metadata.contains("${'$'}{mcace_")) {
            "artifact-mode Fabric remap JAR contains unresolved metadata placeholders"
        }
    }
}

if (smokeArtifactModeEnabled) {
    runClientTask.configure {
        dependsOn(verifySmokeArtifactMode)
    }
}

tasks.test {
    dependsOn(deployableRemapJar)
    inputs.property("mcaceClientBuildId", mcaceClientBuildId)
    systemProperty(
        "mcace.fabric.deployable-jar",
        deployableRemapJar.flatMap { it.archiveFile }.get().asFile.absolutePath,
    )
    systemProperty("mcace.fabric.client-build-id", mcaceClientBuildId)
}

val smokeRunDirectory = providers.gradleProperty("mcaceSmokeRunDirectory")
val smokeServerAddress = providers.gradleProperty("mcaceSmokeServerAddress")
val smokeEvidence = providers.gradleProperty("mcaceSmokeEvidence")

loom {
    runs.named("client") {
        if (smokeRunDirectory.isPresent && smokeServerAddress.isPresent) {
            runDir(smokeRunDirectory.get())
            // The normal smoke exits as soon as authentication completes.  The evidence smoke
            // deliberately keeps the real client open for a human, one-shot consent decision.
            property("mcace.platform-smoke.exit-on-auth-result", (!smokeEvidence.isPresent).toString())
            property("mcace.platform-smoke.await-evidence", smokeEvidence.isPresent.toString())
            property("mcace.platform-smoke.exit-on-evidence-complete", smokeEvidence.isPresent.toString())
            property("mcace.platform-smoke.server-address", smokeServerAddress.get())
        }
    }
}
