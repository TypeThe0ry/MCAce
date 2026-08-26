import groovy.json.JsonSlurper
import java.io.File
import java.security.MessageDigest
import java.util.HexFormat
import java.util.jar.JarFile
import net.fabricmc.loom.api.LoomGradleExtensionAPI
import org.gradle.api.JavaVersion
import org.gradle.api.artifacts.dsl.LockMode
import org.gradle.api.tasks.JavaExec
import org.gradle.api.tasks.compile.JavaCompile
import org.gradle.api.tasks.bundling.AbstractArchiveTask
import org.gradle.api.tasks.testing.Test
import org.gradle.jvm.toolchain.JavaLanguageVersion
import org.gradle.util.GradleVersion

plugins {
    id("base")
    id("net.fabricmc.fabric-loom") version "1.17.19" apply false
}

group = "com.ellan.mcace"
version = providers.gradleProperty("mcaceProductVersion").getOrElse("0.1.0-SNAPSHOT")

require(JavaVersion.current().majorVersion == "25") {
    "fabric-modern must be configured and built by JDK 25; current JVM is " +
        System.getProperty("java.version")
}
require(GradleVersion.current().version == "9.6.1") {
    "fabric-modern must use the root Gradle 9.6.1 wrapper; current Gradle is " +
        GradleVersion.current().version
}

val targetVersions = mapOf(
    "client-26.1.2" to Pair("26.1.2", "0.155.2+26.1.2"),
    "client-26.2" to Pair("26.2", "0.157.0+26.2"),
)
val stagedDependencies = providers.gradleProperty("mcaceRootDepsDir")
    .map { rootProject.file(it) }
    .orElse(rootProject.layout.projectDirectory.dir("../build/fabric-modern-deps").asFile)
val requiredRootJars = setOf(
    "mcace-client-common.jar",
    "mcace-core-client-safe.jar",
    "mcace-sdk.jar",
    "mcace-protocol.jar",
)
val clientSafeCoreClassEntries = setOf(
    "com/ellan/mcace/core/disposition/ArtifactObservation.class",
    "com/ellan/mcace/core/disposition/ArtifactType.class",
    "com/ellan/mcace/core/disposition/Confidence.class",
    "com/ellan/mcace/core/disposition/ObservationOrigin.class",
)
val smokeArtifactMode = providers.gradleProperty("mcaceSmokeArtifactMode")
    .map { configured ->
        require(configured == "true" || configured == "false") {
            "mcaceSmokeArtifactMode must be exactly true or false"
        }
        configured.toBooleanStrict()
    }
    .orElse(false)
val smokeExpectedArtifactSha256 = providers.gradleProperty("mcaceSmokeExpectedArtifactSha256")
val smokeRunToken = providers.gradleProperty("mcaceSmokeRunToken")
val smokeRuntimeArtifactPath = providers.gradleProperty("mcaceSmokeRuntimeArtifactPath")
val smokeRunDirectory = providers.gradleProperty("mcaceSmokeRunDirectory")
val smokeServerAddress = providers.gradleProperty("mcaceSmokeServerAddress")
val smokeEvidence = providers.gradleProperty("mcaceSmokeEvidence")
val dependencyVerificationMetadata = layout.projectDirectory.file(
    "gradle/verification-metadata.xml")
val dependencyLockFiles = targetVersions.keys.map { target ->
    layout.projectDirectory.file("$target/gradle.lockfile")
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

val verifyModernDependencyState = tasks.register("verifyModernDependencyState") {
    group = "verification"
    description = "Validates the exact modern Fabric lockfiles and dependency verification metadata."
    inputs.file(dependencyVerificationMetadata)
        .withPathSensitivity(PathSensitivity.NONE)
    inputs.files(dependencyLockFiles)
        .withPathSensitivity(PathSensitivity.RELATIVE)
    doLast {
        val metadata = dependencyVerificationMetadata.asFile
        check(metadata.isFile && metadata.length() > 0L) {
            "modern dependency verification metadata is missing or empty: $metadata"
        }
        dependencyLockFiles.forEach { lockFile ->
            check(lockFile.asFile.isFile && lockFile.asFile.length() > 0L) {
                "modern dependency lockfile is missing or empty: ${lockFile.asFile}"
            }
        }
    }
}

val verifyStagedRootDependencies = tasks.register("verifyStagedRootDependencies") {
    group = "verification"
    description = "Validates the exact four root JDK 21 JARs supplied to the modern build."
    inputs.dir(stagedDependencies)
        .withPathSensitivity(PathSensitivity.RELATIVE)
    doLast {
        val directory = stagedDependencies.get()
        check(directory.isDirectory) {
            "staged root dependency directory does not exist: $directory"
        }
        val actualNames = directory.listFiles()
            ?.map { it.name }
            ?.toSet()
            .orEmpty()
        check(actualNames == requiredRootJars) {
            "staged root dependency names differ from the exact contract; " +
                "expected=$requiredRootJars actual=$actualNames"
        }
        requiredRootJars.forEach { jarName ->
            val jar = directory.resolve(jarName)
            check(jar.isFile && jar.length() > 0L) {
                "staged root dependency is missing or empty: $jar"
            }
        }
        val clientSafeCoreJar = directory.resolve("mcace-core-client-safe.jar")
        val actualCoreClasses = JarFile(clientSafeCoreJar).use { jar ->
            jar.entries().asSequence()
                .filter { entry ->
                    !entry.isDirectory && entry.name.startsWith("com/ellan/mcace/core/") &&
                        entry.name.endsWith(".class")
                }
                .map { it.name }
                .toSet()
        }
        check(actualCoreClasses == clientSafeCoreClassEntries) {
            "staged client-safe core classes differ from the reviewed allowlist; " +
                "expected=$clientSafeCoreClassEntries actual=$actualCoreClasses"
        }
    }
}

subprojects {
    apply(plugin = "net.fabricmc.fabric-loom")

    group = rootProject.group
    version = rootProject.version

    repositories {
        mavenCentral()
        maven("https://maven.fabricmc.net/") {
            name = "fabric"
        }
    }

    dependencyLocking {
        lockMode.set(LockMode.STRICT)
        lockAllConfigurations()
    }

    val (minecraftVersion, fabricApiVersion) = checkNotNull(targetVersions[name]) {
        "unsupported modern Fabric target $name"
    }
    val mcaceClientBuildId = providers.gradleProperty("mcaceClientBuildId")
        .orElse(providers.gradleProperty("mcaceArtifactSourceCommit")
            .orElse(providers.gradleProperty("mcaceSourceCommit"))
            .map { commit -> "fabric-$minecraftVersion-$commit" })
        .getOrElse("fabric-$minecraftVersion-dev")
    val smokeArtifactModeEnabled = smokeArtifactMode.get()
    val exactReleaseRuntimeMode = smokeArtifactModeEnabled && smokeRuntimeArtifactPath.isPresent
    if (smokeArtifactModeEnabled) {
        require(Regex("(?:platform-smoke-[0-9]{8}T[0-9]{9}Z|[0-9a-f]{32}|fabric-[0-9][0-9.]*-[0-9a-f]{40})")
                .matches(mcaceClientBuildId)) {
            "artifact-mode mcaceClientBuildId must identify either a development smoke " +
                "or the exact release artifact"
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
        require(smokeRunDirectory.isPresent == smokeServerAddress.isPresent) {
            "artifact-mode smoke run directory and server address must be supplied together"
        }
    }
    dependencies {
        add("minecraft", "com.mojang:minecraft:$minecraftVersion")
        add("implementation", "net.fabricmc:fabric-loader:0.19.3")
        add("implementation", "net.fabricmc.fabric-api:fabric-api:$fabricApiVersion")
        requiredRootJars.forEach { jarName ->
            val dependencyFile = providers.provider { stagedDependencies.get().resolve(jarName) }
            add("implementation", files(dependencyFile))
        }
        add("implementation", "com.google.protobuf:protobuf-java:4.32.1")
        add("include", "com.google.protobuf:protobuf-java:4.32.1")
        add("testImplementation", platform("org.junit:junit-bom:5.13.4"))
        add("testImplementation", "org.junit.jupiter:junit-jupiter")
        add("testRuntimeOnly", "org.junit.platform:junit-platform-launcher")
    }

    extensions.configure<org.gradle.api.plugins.JavaPluginExtension> {
        toolchain.languageVersion.set(JavaLanguageVersion.of(25))
    }

    extensions.configure<org.gradle.api.tasks.SourceSetContainer> {
        named("main") {
            java.srcDir(rootProject.file("src/main/java"))
            resources.srcDir(rootProject.file("src/main/resources"))
        }
        named("test") {
            java.srcDir(rootProject.file("src/test/java"))
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        dependsOn(verifyModernDependencyState, verifyStagedRootDependencies)
        options.release.set(25)
        options.encoding = "UTF-8"
        options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
    }

    val deployableJar = tasks.named<org.gradle.api.tasks.bundling.Jar>("jar")
    deployableJar.configure {
        dependsOn(verifyModernDependencyState, verifyStagedRootDependencies)
        archiveFileName.set("mcace-client-fabric-$minecraftVersion-${project.version}.jar")
        duplicatesStrategy = org.gradle.api.file.DuplicatesStrategy.FAIL
        includeEmptyDirs = false
        // Loom 1.17 rejects a file dependency on its `include` configuration because
        // a bare FileCollection has no module capability. Fabric Loader only adds a
        // nested JAR to Knot's classpath when that JAR has its own fabric.mod.json, so
        // merge these four plain JDK 21 libraries into the Java 25 client mod instead.
        requiredRootJars.forEach { jarName ->
            from(providers.provider { zipTree(stagedDependencies.get().resolve(jarName)) }) {
                exclude(
                    "META-INF/MANIFEST.MF",
                    "META-INF/*.SF",
                    "META-INF/*.RSA",
                    "META-INF/*.DSA",
                    "module-info.class",
                    "META-INF/versions/**/module-info.class",
                )
            }
        }
    }
    val smokeRuntimeArtifact = providers.provider {
        if (smokeRuntimeArtifactPath.isPresent) {
            file(smokeRuntimeArtifactPath.get()).canonicalFile
        } else {
            deployableJar.get().archiveFile.get().asFile.canonicalFile
        }
    }

    val loomExtension = extensions.getByType<LoomGradleExtensionAPI>()
    if (smokeArtifactModeEnabled) {
        // Minecraft 26.1+ is distributed in the official named namespace. The normal
        // `jar` task is therefore the production artifact; there is no remapJar stage.
        // Remove every development/source-set mod origin and expose exactly that final
        // named JAR as the one MCAce mod used by Loom's real client run.
        loomExtension.mods.configureEach {
            modFiles.setFrom(emptyList<Any>())
        }
        loomExtension.mods.maybeCreate("mcace").apply {
            modFiles.setFrom(smokeRuntimeArtifact)
        }
    }

    val modernMainOutputRoots = providers.provider {
        rootProject.subprojects.flatMap { modernProject ->
            modernProject.extensions
                .getByType<org.gradle.api.tasks.SourceSetContainer>()
                .getByName(org.gradle.api.tasks.SourceSet.MAIN_SOURCE_SET_NAME)
                .output.files
        }.map { it.canonicalFile.toPath() }.toSet()
    }
    val stagedRootJarPaths = providers.provider {
        requiredRootJars.map { jarName ->
            stagedDependencies.get().resolve(jarName).canonicalFile.toPath()
        }.toSet()
    }
    val forbiddenDevelopmentOrigins = providers.provider {
        modernMainOutputRoots.get() + stagedRootJarPaths.get()
    }
    val runClientTask = tasks.named<JavaExec>("runClient")

    if (smokeArtifactModeEnabled) {
        runClientTask.configure {
            if (!exactReleaseRuntimeMode) {
                dependsOn(deployableJar)
            }
            val developmentClasspath = classpath
            // Loom 1.17 keeps the source-set classpath when a file-backed mod is
            // configured through `loom.mods`; removing that source origin also removes
            // the only classpath entry from which Fabric Loader can discover the mod.
            // Re-add only the final named production JAR so runtime discovery is real.
            classpath = developmentClasspath.filter { candidate ->
                val candidatePath = candidate.canonicalFile.toPath()
                forbiddenDevelopmentOrigins.get().none { forbidden ->
                    candidatePath == forbidden || candidatePath.startsWith(forbidden) ||
                        forbidden.startsWith(candidatePath)
                }
            }.plus(files(smokeRuntimeArtifact))
            doFirst {
                val expectedArtifactSha256 = smokeExpectedArtifactSha256.orNull
                    ?: throw GradleException(
                        "artifact-mode runClient requires " +
                            "-PmcaceSmokeExpectedArtifactSha256=<64 lowercase hex>")
                val runToken = smokeRunToken.orNull
                    ?: throw GradleException(
                        "artifact-mode runClient requires " +
                            "-PmcaceSmokeRunToken=<32 lowercase hex>")
                systemProperty(
                    "mcace.platform-smoke.expected-artifact-sha256",
                    expectedArtifactSha256,
                )
                systemProperty("mcace.smoke.run-token", runToken)
            }
        }
    }

    loomExtension.runs.named("client") {
        if (smokeRunDirectory.isPresent && smokeServerAddress.isPresent) {
            runDirectory.set(file(smokeRunDirectory.get()))
            systemProperties.put(
                "mcace.platform-smoke.exit-on-auth-result",
                (!smokeEvidence.isPresent).toString(),
            )
            systemProperties.put(
                "mcace.platform-smoke.await-evidence",
                smokeEvidence.isPresent.toString(),
            )
            systemProperties.put(
                "mcace.platform-smoke.exit-on-evidence-complete",
                smokeEvidence.isPresent.toString(),
            )
            systemProperties.put("mcace.platform-smoke.server-address", smokeServerAddress.get())
        }
    }

    val verifySmokeArtifactMode = tasks.register("verifySmokeArtifactMode") {
        group = "verification"
        description =
            "Proves that $minecraftVersion smoke startup can only load MCAce from its final named JAR."
        if (!exactReleaseRuntimeMode) {
            dependsOn(deployableJar)
        }
        inputs.property("mcaceSmokeArtifactMode", smokeArtifactMode)
        inputs.property("mcaceClientBuildId", mcaceClientBuildId)
        inputs.file(smokeRuntimeArtifact)

        doLast {
            check(smokeArtifactMode.get()) {
                "verifySmokeArtifactMode requires -PmcaceSmokeArtifactMode=true"
            }
            check(JavaVersion.current().majorVersion == "25") {
                "modern Fabric artifact-mode verification must run on JDK 25"
            }
            val artifact = smokeRuntimeArtifact.get()
            check(artifact.isFile && artifact.length() > 0L) {
                "artifact-mode Fabric named JAR is missing or empty"
            }
            val expectedArtifactSha256 = smokeExpectedArtifactSha256.orNull
                ?: throw GradleException(
                    "verifySmokeArtifactMode requires " +
                        "-PmcaceSmokeExpectedArtifactSha256=<64 lowercase hex>")
            check(sha256(artifact) == expectedArtifactSha256) {
                "artifact-mode Fabric named JAR does not match the operator-started run hash"
            }
            check(smokeRunToken.isPresent) {
                "verifySmokeArtifactMode requires -PmcaceSmokeRunToken=<32 lowercase hex>"
            }

            val nonEmptyMods = loomExtension.mods.mapNotNull { mod ->
                val files = mod.modFiles.files.map { it.canonicalFile }.toSet()
                if (files.isEmpty()) null else mod.name to files
            }
            check(nonEmptyMods == listOf("mcace" to setOf(artifact))) {
                "artifact-mode Loom mods must contain only mcace -> final named JAR"
            }

            val forbiddenOrigins = forbiddenDevelopmentOrigins.get()
            val leakedOrigins = runClientTask.get().classpath.files
                .map { it.canonicalFile.toPath() }
                .filter { candidate ->
                    forbiddenOrigins.any { forbidden ->
                        candidate == forbidden || candidate.startsWith(forbidden) ||
                            forbidden.startsWith(candidate)
                    }
                }
            check(leakedOrigins.isEmpty()) {
                "artifact-mode runClient classpath contains modern main outputs or staged MCAce root JARs"
            }
            check(runClientTask.get().classpath.files.map { it.canonicalFile }.contains(artifact)) {
                "artifact-mode runClient classpath does not contain the final named JAR"
            }
            val conflictingOrigins = runClientTask.get().classpath.files
                .map { it.canonicalFile }
                .filter { it != artifact && containsConflictingMcaceFabricOrigin(it) }
            check(conflictingOrigins.isEmpty()) {
                "artifact-mode runClient classpath contains another MCAce Fabric origin: " +
                    conflictingOrigins.joinToString()
            }

            val (metadataRaw, metadata) = JarFile(artifact).use { jar ->
                val entry = checkNotNull(jar.getJarEntry("fabric.mod.json")) {
                    "artifact-mode Fabric named JAR is missing fabric.mod.json"
                }
                val raw = jar.getInputStream(entry).bufferedReader(Charsets.UTF_8).use { it.readText() }
                val parsed = JsonSlurper().parseText(raw) as? Map<*, *>
                        ?: error("artifact-mode fabric.mod.json is not an object")
                raw to parsed
            }
            check(metadata["id"] == "mcace" && metadata["version"] == project.version.toString()) {
                "artifact-mode Fabric metadata identity is invalid"
            }
            val custom = metadata["custom"] as? Map<*, *>
            check(custom?.get("mcace:client_build_id") == mcaceClientBuildId) {
                "artifact-mode Fabric named JAR does not contain the exact requested build ID"
            }
            val depends = metadata["depends"] as? Map<*, *>
                ?: error("artifact-mode Fabric metadata has no depends object")
            check(depends["minecraft"] == minecraftVersion &&
                    depends["fabric-api"] == fabricApiVersion && depends["java"] == ">=25") {
                "artifact-mode Fabric named JAR dependency identity is invalid"
            }
            check(!metadataRaw.contains("${'$'}{mcace_")) {
                "artifact-mode Fabric named JAR contains unresolved metadata placeholders"
            }
        }
    }

    if (smokeArtifactModeEnabled) {
        runClientTask.configure {
            dependsOn(verifySmokeArtifactMode)
        }
    }

    tasks.withType<Test>().configureEach {
        dependsOn(deployableJar)
        useJUnitPlatform()
        systemProperty("mcace.test.product-version", project.version.toString())
        inputs.file(deployableJar.flatMap { it.archiveFile })
            .withPathSensitivity(PathSensitivity.NONE)
        inputs.property("minecraftVersion", minecraftVersion)
        inputs.property("fabricApiVersion", fabricApiVersion)
        inputs.property("mcaceClientBuildId", mcaceClientBuildId)
        systemProperty(
            "mcace.fabric.deployable-jar",
            deployableJar.flatMap { it.archiveFile }.get().asFile.absolutePath,
        )
        systemProperty("mcace.fabric.minecraft-version", minecraftVersion)
        systemProperty("mcace.fabric.fabric-api-version", fabricApiVersion)
        systemProperty("mcace.fabric.client-build-id", mcaceClientBuildId)
    }

    tasks.withType<AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }

    tasks.named<ProcessResources>("processResources") {
        val resourceProperties = mapOf(
            "mcace_version" to project.version.toString(),
            "mcace_client_build_id" to mcaceClientBuildId,
            "minecraft_version" to minecraftVersion,
            "fabric_api_version" to fabricApiVersion,
        )
        inputs.properties(resourceProperties)
        filesMatching("fabric.mod.json") {
            expand(resourceProperties)
        }
    }

    tasks.register("resolveAndLockAll") {
        group = "build setup"
        description = "Resolves every resolvable configuration for the exact modern Fabric target."
        doLast {
            configurations.filter { it.isCanBeResolved }.forEach { it.resolve() }
        }
    }
}

val modernBuildRuntimeIdentity = layout.buildDirectory.file(
    "modern-build-runtime.properties")
val writeModernBuildRuntimeIdentity = tasks.register("writeModernBuildRuntimeIdentity") {
    group = "build"
    description = "Records the exact JDK 25 and Gradle runtime used for modern Fabric artifacts."
    inputs.property("javaVersion", providers.systemProperty("java.version"))
    inputs.property(
        "javaSpecificationVersion",
        providers.systemProperty("java.specification.version"),
    )
    inputs.property("gradleVersion", GradleVersion.current().version)
    outputs.file(modernBuildRuntimeIdentity)
    doLast {
        val javaSpecificationVersion = System.getProperty("java.specification.version")
        check(javaSpecificationVersion == "25") {
            "modern build runtime identity requires JDK 25; got $javaSpecificationVersion"
        }
        val output = modernBuildRuntimeIdentity.get().asFile
        output.parentFile.mkdirs()
        output.writeText(
            buildString {
                append("schema=MCACE_MODERN_BUILD_RUNTIME_V1\n")
                append("java_version=${System.getProperty("java.version")}\n")
                append("java_specification_version=$javaSpecificationVersion\n")
                append("gradle_version=${GradleVersion.current().version}\n")
            },
            Charsets.UTF_8,
        )
    }
}

val modernSubprojectBuilds = subprojects.map { modernProject ->
    modernProject.tasks.named("build")
}
writeModernBuildRuntimeIdentity.configure {
    dependsOn(modernSubprojectBuilds)
}
tasks.named("build") {
    dependsOn(verifyModernDependencyState, modernSubprojectBuilds, writeModernBuildRuntimeIdentity)
}
tasks.named("clean") {
    dependsOn(subprojects.map { modernProject -> modernProject.tasks.named("clean") })
}
