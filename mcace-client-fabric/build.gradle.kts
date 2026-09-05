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
    // Package only the reviewed client-safe core DTO subset. Compile/test still see
    // mcace-client-common's normal full-core API, so a new client dependency fails
    // the deployable-artifact closure test instead of pulling server code into the mod.
    include(project(mapOf("path" to ":mcace-core", "configuration" to "clientSafeElements")))
    include(project(mapOf("path" to ":mcace-sdk", "configuration" to "runtimeElements")))
    include(project(":mcace-protocol"))
    include("com.google.protobuf:protobuf-java:4.32.1")
}

val mcaceClientBuildId = providers.gradleProperty("mcaceClientBuildId")
    .orElse(providers.gradleProperty("mcaceArtifactSourceCommit")
        .orElse(providers.gradleProperty("mcaceSourceCommit"))
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
val smokeRuntimeArtifactPath = providers.gradleProperty("mcaceSmokeRuntimeArtifactPath")
val smokeRunDirectory = providers.gradleProperty("mcaceSmokeRunDirectory")
val smokeServerAddress = providers.gradleProperty("mcaceSmokeServerAddress")
val smokeEvidence = providers.gradleProperty("mcaceSmokeEvidence")
val smokeConsentTimeoutSeconds = providers.gradleProperty("mcaceSmokeConsentTimeoutSeconds")
    .map { configured ->
        val seconds = configured.toIntOrNull()
            ?: throw GradleException("mcaceSmokeConsentTimeoutSeconds must be an integer")
        require(seconds in 30..300) {
            "mcaceSmokeConsentTimeoutSeconds must be between 30 and 300 seconds"
        }
        seconds
    }
    .orElse(30)
val exactReleaseRuntimeMode = smokeArtifactModeEnabled && smokeRuntimeArtifactPath.isPresent

if (smokeArtifactModeEnabled) {
    require(Regex("(?:platform-smoke-[0-9]{8}T[0-9]{9}Z|[0-9a-f]{32}|fabric-1\\.21\\.11-[0-9a-f]{40})")
            .matches(mcaceClientBuildId)) {
        "artifact-mode mcaceClientBuildId must identify either a development smoke or the exact release artifact"
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
// Loom's production remap JAR is in intermediary namespace.  The 1.21.11
// `runClient` task is a named-namespace development launch, so it needs a
// separate, deterministic named smoke JAR.  The release artifact remains the
// remap JAR above; this small runtime JAR is only the launch adapter used by
// the GUI gate and is never copied into the release bundle.
val smokeNamedJar = tasks.register<org.gradle.api.tasks.bundling.Jar>("smokeNamedJar") {
    archiveFileName.set("mcace-client-fabric-$mcaceVersion-smoke-named.jar")
    destinationDirectory.set(layout.buildDirectory.dir("smoke-libs"))
    dependsOn(tasks.named("classes"))
    from(sourceSets.main.get().output)
    duplicatesStrategy = org.gradle.api.file.DuplicatesStrategy.FAIL
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}
val smokeRuntimeArtifact = providers.provider {
    if (smokeRuntimeArtifactPath.isPresent) {
        file(smokeRuntimeArtifactPath.get()).canonicalFile
    } else {
        smokeNamedJar.get().archiveFile.get().asFile.canonicalFile
    }
}

if (smokeArtifactModeEnabled && !exactReleaseRuntimeMode) {
    // Loom normally exposes this project's main source-set outputs as the development mod.
    // In artifact mode every configured mod is first emptied, then the one MCAce mod is
    // bound exclusively to the final production remap JAR.
    loom.mods.configureEach {
        modFiles.setFrom(emptyList<Any>())
    }
    loom.mods.maybeCreate("mcace").apply {
        modFiles.setFrom(smokeNamedJar)
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
        if (!exactReleaseRuntimeMode) {
            dependsOn(deployableRemapJar)
        }
        val developmentClasspath = classpath
        // `loom.mods` contributes the class-path-group metadata, but Loom 1.14 does not
        // append a file-backed mod to the JavaExec classpath after the source-set mod has
        // been removed.  Keep the run genuinely artifact-only by filtering every MCAce
        // source output and explicitly putting the final remap JAR back on the classpath.
        val filteredClasspath = developmentClasspath.filter { candidate ->
            val candidatePath = candidate.canonicalFile.toPath()
            mcaceMainOutputRoots.get().none { outputRoot ->
                candidatePath.startsWith(outputRoot) || outputRoot.startsWith(candidatePath)
            }
        }
        if (!exactReleaseRuntimeMode) {
            classpath = filteredClasspath.plus(files(smokeNamedJar))
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
            // Keep the legacy development run on the same connection-bound consent
            // budget as the smoke runner.  Without this bridge the Gradle project
            // property is validated but the client controller silently falls back
            // to its 30-second default.
            systemProperty(
                "mcace.client.enablement-decision-timeout-seconds",
                smokeConsentTimeoutSeconds.get().toString(),
            )
        }
    }
}

val verifySmokeArtifactMode = tasks.register("verifySmokeArtifactMode") {
    group = "verification"
    description = "Proves that Fabric smoke startup can only load MCAce from the final remap JAR."
    if (!exactReleaseRuntimeMode) {
        dependsOn(deployableRemapJar, smokeNamedJar)
    }
    inputs.property("mcaceSmokeArtifactMode", smokeArtifactMode)
    inputs.property("mcaceClientBuildId", mcaceClientBuildId)
    if (exactReleaseRuntimeMode) {
        inputs.file(smokeRuntimeArtifact)
    } else {
        inputs.file(deployableRemapJar.flatMap { it.archiveFile })
        inputs.file(smokeNamedJar.flatMap { it.archiveFile })
    }

    doLast {
        check(smokeArtifactMode.get()) {
            "verifySmokeArtifactMode requires -PmcaceSmokeArtifactMode=true"
        }
        val runtimeArtifact = smokeRuntimeArtifact.get()
        check(runtimeArtifact.isFile && runtimeArtifact.length() > 0L) {
            "artifact-mode Fabric named smoke JAR is missing or empty"
        }
        val expectedArtifactSha256 = smokeExpectedArtifactSha256.orNull
            ?: throw GradleException(
                "verifySmokeArtifactMode requires -PmcaceSmokeExpectedArtifactSha256=<64 lowercase hex>")
        check(sha256(runtimeArtifact) == expectedArtifactSha256) {
            "artifact-mode Fabric named smoke JAR does not match the operator-started run hash"
        }
        check(smokeRunToken.isPresent) {
            "verifySmokeArtifactMode requires -PmcaceSmokeRunToken=<32 lowercase hex>"
        }

        if (!exactReleaseRuntimeMode) {
            val nonEmptyMods = loom.mods.mapNotNull { mod ->
                val files = mod.modFiles.files.map { it.canonicalFile }.toSet()
                if (files.isEmpty()) null else mod.name to files
            }
            check(nonEmptyMods == listOf("mcace" to setOf(runtimeArtifact))) {
                "artifact-mode Loom mods must contain only mcace -> named smoke JAR"
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
            check(runClientTask.get().classpath.files.map { it.canonicalFile }.contains(runtimeArtifact)) {
                "artifact-mode runClient classpath does not contain the named smoke JAR"
            }
            val conflictingOrigins = runClientTask.get().classpath.files
                .map { it.canonicalFile }
                .filter { it != runtimeArtifact && containsConflictingMcaceFabricOrigin(it) }
            check(conflictingOrigins.isEmpty()) {
                "artifact-mode runClient classpath contains another MCAce Fabric origin: " +
                    conflictingOrigins.joinToString()
            }
        }

        val metadata = JarFile(runtimeArtifact).use { jar ->
            val entry = checkNotNull(jar.getJarEntry("fabric.mod.json")) {
                "artifact-mode Fabric runtime JAR is missing fabric.mod.json"
            }
            jar.getInputStream(entry).bufferedReader(Charsets.UTF_8).use { it.readText() }
        }
        val expectedBuildIdentity = Regex(
            "\\\"mcace:client_build_id\\\"\\s*:\\s*\\\"${Regex.escape(mcaceClientBuildId)}\\\""
        )
        check(expectedBuildIdentity.findAll(metadata).count() == 1) {
            "artifact-mode Fabric runtime JAR does not contain the exact requested build ID"
        }
        check(!metadata.contains("${'$'}{mcace_")) {
            "artifact-mode Fabric runtime JAR contains unresolved metadata placeholders"
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
            // Loom's generated JavaExec path is independent of the task-level
            // doFirst above; propagate the same budget into the named client run.
            property(
                "mcace.client.enablement-decision-timeout-seconds",
                smokeConsentTimeoutSeconds.get().toString(),
            )
        }
    }
}

val productionFabricApi = configurations.detachedConfiguration(
    dependencies.create("net.fabricmc.fabric-api:fabric-api:0.141.6+1.21.11"),
).apply { isTransitive = false }
val productionIntermediary = configurations.detachedConfiguration(
    dependencies.create("net.fabricmc:intermediary:1.21.11:v2"),
).apply { isTransitive = false }
val productionMinecraftClient = providers.provider {
    File(gradle.gradleUserHomeDir, "caches/fabric-loom/1.21.11/minecraft-client.jar")
        .canonicalFile
}
val productionNativeDirectory = rootProject.layout.projectDirectory
    .dir(".gradle/loom-cache/natives/1.21.11")
val productionAssetsDirectory = providers.provider {
    File(gradle.gradleUserHomeDir, "caches/fabric-loom/assets").canonicalFile
}
val productionRuntimeClasspath = configurations.runtimeClasspath.get().filter { candidate ->
    val path = candidate.canonicalPath.replace('\\', '/').lowercase()
    !path.contains("/build/classes/") &&
        !path.contains("/build/resources/") &&
        !path.contains("/build/libs/") &&
        !path.contains("/remapped_mods/") &&
        !path.contains("/minecraftmaven/") &&
        !path.endsWith("/mappings.jar") &&
        !path.contains("/dev-launch-injector/") &&
        !path.contains("/net.fabricmc.fabric-api/fabric-api/")
}

val runReleaseClient = tasks.register<org.gradle.api.tasks.JavaExec>("runReleaseClient") {
    group = "fabric"
    description =
        "Runs Minecraft in the production intermediary namespace with the exact protected release JAR."
    dependsOn(verifySmokeArtifactMode, tasks.named("downloadAssets"), tasks.named("generateLog4jConfig"))
    onlyIf {
        check(exactReleaseRuntimeMode) {
            "runReleaseClient requires -PmcaceSmokeArtifactMode=true and " +
                "-PmcaceSmokeRuntimeArtifactPath=<exact release JAR>"
        }
        true
    }
    mainClass.set("net.fabricmc.loader.impl.launch.knot.KnotClient")
    classpath = productionRuntimeClasspath
        .plus(productionIntermediary)
        .plus(files(productionMinecraftClient))
    if (smokeRunDirectory.isPresent) {
        workingDir(file(smokeRunDirectory.get()))
    }
    jvmArgs("-Xms128m", "-Xmx1024m")
    if (smokeRunDirectory.isPresent) {
        val runDirectory = file(smokeRunDirectory.get()).canonicalFile
        args(
            "--username", "Player817",
            "--version", "fabric-loader-0.19.3-1.21.11",
            "--gameDir", runDirectory.absolutePath,
            "--assetsDir", productionAssetsDirectory.get().absolutePath,
            "--assetIndex", "1.21.11-29",
            "--uuid", "00000000-0000-0000-0000-000000000817",
            "--accessToken", "0",
            "--clientId", "0",
            "--xuid", "0",
            "--versionType", "release",
        )
    }
    doFirst {
        val runtimeArtifact = smokeRuntimeArtifact.get()
        val expectedArtifactSha256 = smokeExpectedArtifactSha256.orNull
            ?: throw GradleException(
                "runReleaseClient requires -PmcaceSmokeExpectedArtifactSha256=<64 lowercase hex>")
        val runToken = smokeRunToken.orNull
            ?: throw GradleException("runReleaseClient requires -PmcaceSmokeRunToken=<32 lowercase hex>")
        val runDirectory = file(checkNotNull(smokeRunDirectory.orNull) {
            "runReleaseClient requires -PmcaceSmokeRunDirectory=<dedicated run directory>"
        }).canonicalFile
        val serverAddress = checkNotNull(smokeServerAddress.orNull) {
            "runReleaseClient requires -PmcaceSmokeServerAddress=<host:port>"
        }
        val minecraftClient = productionMinecraftClient.get()
        val nativeDirectory = productionNativeDirectory.asFile
        check(runtimeArtifact.isFile && sha256(runtimeArtifact) == expectedArtifactSha256) {
            "runReleaseClient exact release JAR is missing or changed"
        }
        check(minecraftClient.isFile && minecraftClient.length() > 0L) {
            "runReleaseClient verified Minecraft production client cache is missing"
        }
        check(nativeDirectory.isDirectory && nativeDirectory.listFiles()?.isNotEmpty() == true) {
            "runReleaseClient verified Minecraft native cache is missing"
        }
        val modsDirectory = runDirectory.resolve("mods")
        check(modsDirectory.isDirectory && modsDirectory.listFiles()?.isEmpty() == true) {
            "runReleaseClient requires an existing empty dedicated mods directory"
        }
        val runtimeCopy = modsDirectory.resolve("mcace.jar")
        val fabricApiCopy = modsDirectory.resolve("fabric-api.jar")
        runtimeArtifact.copyTo(runtimeCopy, overwrite = false)
        productionFabricApi.singleFile.copyTo(fabricApiCopy, overwrite = false)
        check(sha256(runtimeCopy) == expectedArtifactSha256) {
            "runReleaseClient copied release JAR does not preserve the protected SHA-256"
        }
        systemProperty("fabric.development", "false")
        systemProperty("fabric.gameVersion", "1.21.11")
        systemProperty("mcace.platform-smoke.expected-artifact-sha256", expectedArtifactSha256)
        systemProperty("mcace.smoke.run-token", runToken)
        // The release-client task bypasses Loom's named `client` run configuration. Keep the
        // connection-bound consent window aligned with the smoke runner's human transition
        // budget instead of silently falling back to the 30-second fail-closed default.
        systemProperty(
            "mcace.client.enablement-decision-timeout-seconds",
            smokeConsentTimeoutSeconds.get().toString(),
        )
        systemProperty("mcace.platform-smoke.server-address", serverAddress)
        systemProperty("mcace.platform-smoke.exit-on-auth-result", (!smokeEvidence.isPresent).toString())
        systemProperty("mcace.platform-smoke.await-evidence", smokeEvidence.isPresent.toString())
        systemProperty("mcace.platform-smoke.exit-on-evidence-complete", smokeEvidence.isPresent.toString())
        systemProperty("java.library.path", nativeDirectory.absolutePath)
        systemProperty("jna.tmpdir", nativeDirectory.absolutePath)
        systemProperty("org.lwjgl.system.SharedLibraryExtractPath", nativeDirectory.absolutePath)
        systemProperty("io.netty.native.workdir", nativeDirectory.absolutePath)
        systemProperty("log4j.configurationFile", file(".gradle/loom-cache/log4j.xml").absolutePath)
        systemProperty("log4j2.formatMsgNoLookups", "true")
    }
}
