import groovy.json.JsonSlurper
import org.gradle.api.JavaVersion
import org.gradle.api.artifacts.dsl.LockMode
import org.gradle.api.tasks.compile.JavaCompile
import org.gradle.api.tasks.bundling.AbstractArchiveTask
import org.gradle.api.tasks.bundling.Jar
import org.gradle.api.tasks.testing.Test
import org.gradle.jvm.toolchain.JavaLanguageVersion
import org.gradle.util.GradleVersion
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.HexFormat
import java.util.Properties
import java.util.jar.JarFile

plugins {
    id("base")
}

abstract class MCAceReleaseBundleTask : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val fabric12111Jar: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val fabric2612Jar: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val fabric262Jar: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val velocityJar: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val bungeeJar: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val paperJar: RegularFileProperty

    @get:Input
    abstract val sourceCommit: Property<String>

    @get:Input
    abstract val productVersion: Property<String>

    @get:Input
    abstract val bundleProfile: Property<String>

    @get:Input
    abstract val fabric12111BuildId: Property<String>

    @get:Input
    abstract val fabric2612BuildId: Property<String>

    @get:Input
    abstract val fabric262BuildId: Property<String>

    @get:Input
    abstract val rootJavaVersion: Property<String>

    @get:Input
    abstract val rootGradleVersion: Property<String>

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val modernRuntimeIdentity: RegularFileProperty

    @get:Internal
    abstract val repositoryDirectory: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    private fun sha256(path: Path): String {
        val digest = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(path).use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) {
                    break
                }
                digest.update(buffer, 0, read)
            }
        }
        return HexFormat.of().formatHex(digest.digest())
    }

    private fun git(vararg arguments: String): String {
        val command = mutableListOf("git")
        command.addAll(arguments)
        val process = ProcessBuilder(command)
            .directory(repositoryDirectory.get().asFile)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().use { it.readText() }.trim()
        val exitCode = process.waitFor()
        check(exitCode == 0) {
            "releaseBundle could not verify Git source identity: ${command.joinToString(" ")} " +
                "exited $exitCode${if (output.isEmpty()) "" else ": $output"}"
        }
        return output
    }

    private fun verifyExactSourceIdentity(commit: String) {
        val actualHead = git("rev-parse", "--verify", "HEAD")
        require(actualHead == commit) {
            "mcaceSourceCommit $commit does not match checked-out HEAD $actualHead"
        }
        val worktreeStatus = git("status", "--porcelain=v1", "--untracked-files=all")
        require(worktreeStatus.isEmpty()) {
            "an exact-commit releaseBundle requires a clean worktree; Git reported:\n$worktreeStatus"
        }
    }

    private fun verifySourceIdentity(profile: String, commit: String) {
        when (profile) {
            "RELEASE" -> {
                require(commit.matches(Regex("[0-9a-f]{40}|[0-9a-f]{64}"))) {
                    "releaseBundle requires -PmcaceSourceCommit=<lowercase 40/64-character Git object id>"
                }
                verifyExactSourceIdentity(commit)
            }
            "LOCAL_VERIFICATION" -> require(commit == "LOCAL_UNSPECIFIED") {
                "localVerificationBundle must use source_commit=LOCAL_UNSPECIFIED"
            }
            else -> throw IllegalArgumentException("unsupported bundle profile $profile")
        }
    }

    private fun verifyFabricArtifact(
        path: Path,
        expectedMinecraftVersion: String,
        expectedFabricLoaderVersion: String,
        expectedFabricApiVersion: String,
        expectedJavaVersion: String,
        expectedBuildId: String,
    ) {
        require(Regex("[A-Za-z0-9][A-Za-z0-9._+\\-]{0,127}").matches(expectedBuildId)) {
            "expected Fabric build ID is not a safe immutable marker: $expectedBuildId"
        }
        val metadata = JarFile(path.toFile()).use { jar ->
            val entry = requireNotNull(jar.getJarEntry("fabric.mod.json")) {
                "Fabric deployable is missing fabric.mod.json: $path"
            }
            jar.getInputStream(entry).buffered().use { input ->
                JsonSlurper().parse(input) as? Map<*, *>
                    ?: throw IllegalArgumentException("Fabric metadata is not a JSON object: $path")
            }
        }
        require(metadata["schemaVersion"] == 1
                && metadata["id"] == "mcace"
                && metadata["version"] == productVersion.get()
                && metadata["environment"] == "client") {
            "Fabric deployable has the wrong mod/product identity: $path"
        }
        val entrypoints = metadata["entrypoints"] as? Map<*, *>
            ?: throw IllegalArgumentException("Fabric deployable has no entrypoints object: $path")
        require(entrypoints["client"] == listOf("com.ellan.mcace.fabric.MCAceFabricClient")) {
            "Fabric deployable has the wrong client entrypoint: $path"
        }
        val custom = metadata["custom"] as? Map<*, *>
            ?: throw IllegalArgumentException("Fabric deployable has no custom metadata object: $path")
        require(custom["mcace:client_build_id"] == expectedBuildId) {
            "Fabric deployable build ID does not match its exact release identity: $path"
        }
        val depends = metadata["depends"] as? Map<*, *>
            ?: throw IllegalArgumentException("Fabric deployable has no depends metadata object: $path")
        require(depends["fabricloader"] == expectedFabricLoaderVersion
                && depends["minecraft"] == expectedMinecraftVersion
                && depends["fabric-api"] == expectedFabricApiVersion
                && depends["java"] == expectedJavaVersion) {
            "Fabric deployable dependency identity does not match its exact target: $path"
        }
    }

    @TaskAction
    fun createBundle() {
        require(JavaVersion.current() == JavaVersion.VERSION_21) {
            "releaseBundle must run on JDK 21; current JVM is ${System.getProperty("java.version")}"
        }
        require(rootGradleVersion.get() == "9.6.1") {
            "bundle creation must use Gradle 9.6.1; current Gradle is ${rootGradleVersion.get()}"
        }
        val profile = bundleProfile.get()
        val commit = sourceCommit.get()
        verifySourceIdentity(profile, commit)
        val clientBuildIds = listOf(
            fabric12111BuildId.get(),
            fabric2612BuildId.get(),
            fabric262BuildId.get(),
        )
        require(clientBuildIds.distinct().size == clientBuildIds.size) {
            "each supported Fabric target must have a different immutable build ID: $clientBuildIds"
        }
        val artifacts = linkedMapOf(
            "mcace-client-fabric-1.21.11.jar" to fabric12111Jar.get().asFile.toPath(),
            "mcace-client-fabric-26.1.2.jar" to fabric2612Jar.get().asFile.toPath(),
            "mcace-client-fabric-26.2.jar" to fabric262Jar.get().asFile.toPath(),
            "mcace-server-velocity.jar" to velocityJar.get().asFile.toPath(),
            "mcace-server-bungeecord.jar" to bungeeJar.get().asFile.toPath(),
            "mcace-server-paper.jar" to paperJar.get().asFile.toPath(),
        )
        artifacts.forEach { (_, source) ->
            require(Files.isRegularFile(source) && Files.size(source) > 0L) {
                "deployable artifact is missing or empty: $source"
            }
        }
        val fabricIdentities = linkedMapOf(
            "mcace-client-fabric-1.21.11.jar" to Pair("1.21.11", fabric12111BuildId.get()),
            "mcace-client-fabric-26.1.2.jar" to Pair("26.1.2", fabric2612BuildId.get()),
            "mcace-client-fabric-26.2.jar" to Pair("26.2", fabric262BuildId.get()),
        )
        verifyFabricArtifact(
            artifacts.getValue("mcace-client-fabric-1.21.11.jar"),
            "1.21.11",
                    ">=0.19.3",
            "0.141.6+1.21.11",
            ">=21",
            fabric12111BuildId.get(),
        )
        verifyFabricArtifact(
            artifacts.getValue("mcace-client-fabric-26.1.2.jar"),
            "26.1.2",
            ">=0.19.3",
            "0.155.2+26.1.2",
            ">=25",
            fabric2612BuildId.get(),
        )
        verifyFabricArtifact(
            artifacts.getValue("mcace-client-fabric-26.2.jar"),
            "26.2",
            ">=0.19.3",
            "0.157.0+26.2",
            ">=25",
            fabric262BuildId.get(),
        )
        val modernIdentity = Properties().apply {
            modernRuntimeIdentity.get().asFile.inputStream().buffered().use(::load)
        }
        require(modernIdentity.getProperty("schema") == "MCACE_MODERN_BUILD_RUNTIME_V1") {
            "modern build runtime identity has an unsupported schema"
        }
        val modernJavaVersion = requireNotNull(modernIdentity.getProperty("java_version")) {
            "modern build runtime identity is missing java_version"
        }
        val modernJavaSpecificationVersion = requireNotNull(
            modernIdentity.getProperty("java_specification_version")) {
            "modern build runtime identity is missing java_specification_version"
        }
        require(modernJavaSpecificationVersion == "25") {
            "modern Fabric artifacts must be built on JDK 25; identity reported " +
                modernJavaSpecificationVersion
        }
        val modernGradleVersion = requireNotNull(modernIdentity.getProperty("gradle_version")) {
            "modern build runtime identity is missing gradle_version"
        }
        require(modernGradleVersion == "9.6.1") {
            "modern Fabric artifacts must be built with Gradle 9.6.1; identity reported " +
                modernGradleVersion
        }

        // Validate every source artifact and both build-runtime identities before replacing
        // any retained bundle. A failed release assertion must leave the prior bundle intact.
        val output = outputDirectory.get().asFile.toPath()
        output.toFile().deleteRecursively()
        Files.createDirectories(output)
        val hashes = linkedMapOf<String, String>()
        artifacts.forEach { (name, source) ->
            val destination = output.resolve(name)
            Files.copy(source, destination, StandardCopyOption.REPLACE_EXISTING)
            hashes[name] = sha256(destination)
        }
        val checksumsText = hashes.entries.joinToString(
            separator = "\n", postfix = "\n") { (name, hash) -> "$hash  $name" }
        val releaseIdentity = profile == "RELEASE"
        val manifestSchema = if (releaseIdentity) {
            "MCACE_RELEASE_BUNDLE_V3"
        } else {
            "MCACE_LOCAL_VERIFICATION_BUNDLE_V1"
        }
        val manifestText = buildString {
            append("schema=$manifestSchema\n")
            append("bundle_profile=$profile\n")
            append("release_identity=$releaseIdentity\n")
            append("deployable_count=6\n")
            append("bundle_entry_count=8\n")
            append("product_version=${productVersion.get()}\n")
            append("source_commit=$commit\n")
            append("root_java_version=${rootJavaVersion.get()}\n")
            append("root_java_specification_version=21\n")
            append("root_gradle_version=${rootGradleVersion.get()}\n")
            append("modern_java_version=$modernJavaVersion\n")
            append("modern_java_specification_version=$modernJavaSpecificationVersion\n")
            append("modern_gradle_version=$modernGradleVersion\n")
            hashes.forEach { (name, hash) ->
                val key = name.removeSuffix(".jar").replace('-', '_').replace('.', '_')
                append("artifact.$key.file=$name\n")
                append("artifact.$key.sha256=$hash\n")
                fabricIdentities[name]?.let { (minecraftVersion, buildId) ->
                    append("artifact.$key.minecraft_version=$minecraftVersion\n")
                    append("artifact.$key.client_build_id=$buildId\n")
                }
            }
        }
        Files.writeString(output.resolve("SHA256SUMS"), checksumsText)
        Files.writeString(output.resolve("release-manifest.properties"), manifestText)

        val expectedNames = artifacts.keys + setOf("SHA256SUMS", "release-manifest.properties")
        val actualNames = Files.list(output).use { stream ->
            stream.map { it.fileName.toString() }.toList().toSet()
        }
        check(actualNames == expectedNames) {
            "release bundle entries differ from the exact eight-file contract; " +
                "expected=$expectedNames actual=$actualNames"
        }
        hashes.forEach { (name, expectedHash) ->
            val retainedHash = sha256(output.resolve(name))
            check(retainedHash == expectedHash) {
                "release artifact changed after hashing: $name"
            }
        }
        check(Files.readString(output.resolve("SHA256SUMS")) == checksumsText) {
            "retained SHA256SUMS differs from the generated checksum contract"
        }
        check(Files.readString(output.resolve("release-manifest.properties")) == manifestText) {
            "retained release-manifest.properties differs from the generated identity contract"
        }
    }
}

allprojects {
    group = "com.ellan.mcace"
    version = "0.1.0-SNAPSHOT"

    repositories {
        mavenCentral()
        maven("https://repo.papermc.io/repository/maven-public/") {
            name = "papermc"
        }
    }

    dependencyLocking {
        lockAllConfigurations()
        lockMode.set(LockMode.STRICT)
    }
}

subprojects {
    apply(plugin = "java-library")

    extensions.configure<JavaPluginExtension> {
        toolchain.languageVersion.set(JavaLanguageVersion.of(21))
        withSourcesJar()
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.release.set(21)
        options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
    }

    dependencies {
        "testImplementation"(platform("org.junit:junit-bom:5.13.4"))
        "testImplementation"("org.junit.jupiter:junit-jupiter")
        "testRuntimeOnly"("org.junit.platform:junit-platform-launcher")
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        testLogging {
            events("failed", "skipped")
        }
    }

    tasks.withType<AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }

    tasks.register("resolveAndLockAll") {
        description = "Resolves every resolvable configuration for dependency lock/verification updates."
        notCompatibleWithConfigurationCache(
            "Dependency lock maintenance intentionally resolves the project's configuration container at execution time.")
        doLast {
            configurations.filter { it.isCanBeResolved }.forEach { it.resolve() }
        }
    }
}

val modernFabricProjectDirectory = layout.projectDirectory.dir("fabric-modern")
val stagedModernDependenciesDirectory = layout.buildDirectory.dir("fabric-modern-deps")
val stagedModernDependencyNames = setOf(
    "mcace-client-common.jar",
    "mcace-core.jar",
    "mcace-sdk.jar",
    "mcace-protocol.jar",
)

val clientCommonJar = project(":mcace-client-common").tasks.named<Jar>("jar")
val coreJar = project(":mcace-core").tasks.named<Jar>("jar")
val sdkJar = project(":mcace-sdk").tasks.named<Jar>("jar")
val protocolJar = project(":mcace-protocol").tasks.named<Jar>("jar")

val stageModernFabricDeps = tasks.register<Sync>("stageModernFabricDeps") {
    group = "build setup"
    description = "Stages the exact root JDK 21 library JAR set consumed by the JDK 25 Fabric build."
    dependsOn(clientCommonJar, coreJar, sdkJar, protocolJar)
    into(stagedModernDependenciesDirectory)
    includeEmptyDirs = false
    duplicatesStrategy = DuplicatesStrategy.FAIL
    from(clientCommonJar.flatMap { it.archiveFile }) {
        rename { "mcace-client-common.jar" }
    }
    from(coreJar.flatMap { it.archiveFile }) {
        rename { "mcace-core.jar" }
    }
    from(sdkJar.flatMap { it.archiveFile }) {
        rename { "mcace-sdk.jar" }
    }
    from(protocolJar.flatMap { it.archiveFile }) {
        rename { "mcace-protocol.jar" }
    }
    doLast {
        val stagedDirectory = destinationDir.toPath()
        val actualNames = Files.list(stagedDirectory).use { entries ->
            entries.map { it.fileName.toString() }.toList().toSet()
        }
        check(actualNames == stagedModernDependencyNames) {
            "staged modern dependency names differ from the exact contract; " +
                "expected=$stagedModernDependencyNames actual=$actualNames"
        }
        stagedModernDependencyNames.forEach { name ->
            val stagedJar = stagedDirectory.resolve(name)
            check(Files.isRegularFile(stagedJar) && Files.size(stagedJar) > 0L) {
                "staged modern dependency is missing or empty: $stagedJar"
            }
        }
    }
}

val cleanModernFabric = tasks.register<Delete>("cleanModernFabric") {
    group = "build"
    description = "Deletes every output directory owned by the isolated modern Fabric build."
    delete(
        modernFabricProjectDirectory.dir("build"),
        modernFabricProjectDirectory.dir("client-26.1.2/build"),
        modernFabricProjectDirectory.dir("client-26.2/build"),
    )
}

val modernJavaHome = providers.gradleProperty("mcaceModernJavaHome")
    .orElse(providers.environmentVariable("MCACE_JAVA25_HOME"))
val sourceCommitProperty = providers.gradleProperty("mcaceSourceCommit")
val explicitClientBuildId = providers.gradleProperty("mcaceClientBuildId")
val configuredFabric12111BuildId = explicitClientBuildId
    .orElse(sourceCommitProperty.map { commit -> "fabric-1.21.11-$commit" })
    .orElse("fabric-phase2-dev")
val configuredFabric2612BuildId = explicitClientBuildId
    .orElse(sourceCommitProperty.map { commit -> "fabric-26.1.2-$commit" })
    .orElse("fabric-26.1.2-dev")
val configuredFabric262BuildId = explicitClientBuildId
    .orElse(sourceCommitProperty.map { commit -> "fabric-26.2-$commit" })
    .orElse("fabric-26.2-dev")
val modernFabric2612Jar = modernFabricProjectDirectory.file(
    "client-26.1.2/build/libs/mcace-client-fabric-26.1.2-${project.version}.jar")
val modernFabric262Jar = modernFabricProjectDirectory.file(
    "client-26.2/build/libs/mcace-client-fabric-26.2-${project.version}.jar")
val modernRuntimeIdentityFile = modernFabricProjectDirectory.file(
    "build/modern-build-runtime.properties")

val modernFabricNestedInvariantArguments = listOf(
    "--dependency-verification=strict",
    "--rerun-tasks",
    "--no-build-cache",
    "--no-configuration-cache",
    "--no-daemon",
    "--no-parallel",
    "--max-workers=1",
    "--console=plain",
)

fun modernFabricNestedExecutionArguments(offline: Boolean): List<String> = buildList {
    addAll(modernFabricNestedInvariantArguments)
    if (offline) {
        add("--offline")
    }
}

val verifyModernFabricInvocationContract = tasks.register("verifyModernFabricInvocationContract") {
    group = "verification"
    description =
        "Verifies that the isolated JDK 25 invocation cannot reuse stale modern Fabric outputs."
    inputs.property("nestedInvariantArguments", modernFabricNestedInvariantArguments)
    doLast {
        val expectedInvariantArguments = listOf(
            "--dependency-verification=strict",
            "--rerun-tasks",
            "--no-build-cache",
            "--no-configuration-cache",
            "--no-daemon",
            "--no-parallel",
            "--max-workers=1",
            "--console=plain",
        )
        check(modernFabricNestedExecutionArguments(offline = false) == expectedInvariantArguments) {
            "modern Fabric nested invocation lost an invariant execution argument"
        }
        check(modernFabricNestedExecutionArguments(offline = true) ==
                expectedInvariantArguments + "--offline") {
            "modern Fabric nested invocation does not propagate strict offline execution"
        }
    }
}

val modernFabricBuild = tasks.register<Exec>("modernFabricBuild") {
    group = "build"
    description = "Builds Fabric 26.1.2 and 26.2 in an isolated Gradle invocation on explicit JDK 25."
    dependsOn(stageModernFabricDeps, verifyModernFabricInvocationContract)
    mustRunAfter(cleanModernFabric)
    inputs.files(fileTree(modernFabricProjectDirectory) {
        exclude("**/.gradle/**", "**/build/**")
    }).withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.dir(stagedModernDependenciesDirectory)
        .withPathSensitivity(PathSensitivity.RELATIVE)
    inputs.file(layout.projectDirectory.file("gradlew"))
        .withPathSensitivity(PathSensitivity.NONE)
    inputs.file(layout.projectDirectory.file("gradlew.bat"))
        .withPathSensitivity(PathSensitivity.NONE)
    inputs.file(layout.projectDirectory.file("gradle/wrapper/gradle-wrapper.properties"))
        .withPathSensitivity(PathSensitivity.NONE)
    inputs.property("mcaceModernJavaHome", modernJavaHome.orElse("<missing>"))
    inputs.property("mcaceSourceCommit", sourceCommitProperty.orElse("<missing>"))
    inputs.property("mcaceClientBuildId", explicitClientBuildId.orElse("<target-default>"))
    inputs.property("mcaceProductVersion", project.version.toString())
    inputs.property("offline", gradle.startParameter.isOffline)
    inputs.property(
        "nestedExecutionArguments",
        modernFabricNestedExecutionArguments(gradle.startParameter.isOffline),
    )
    outputs.files(modernFabric2612Jar, modernFabric262Jar, modernRuntimeIdentityFile)

    doFirst {
        val javaHome = modernJavaHome.orNull?.let(::File)
            ?: throw GradleException(
                "modernFabricBuild requires -PmcaceModernJavaHome=<JDK 25 home> " +
                    "or MCACE_JAVA25_HOME")
        check(javaHome.isDirectory) {
            "mcaceModernJavaHome is not a directory: $javaHome"
        }
        val windows = System.getProperty("os.name").startsWith("Windows", ignoreCase = true)
        val javaExecutable = javaHome.resolve("bin").resolve(if (windows) "java.exe" else "java")
        check(javaExecutable.isFile) {
            "mcaceModernJavaHome has no Java executable: $javaExecutable"
        }

        val arguments = mutableListOf(
            "--project-dir", modernFabricProjectDirectory.asFile.absolutePath,
            "build",
            "-PmcaceRootDepsDir=${stagedModernDependenciesDirectory.get().asFile.absolutePath}",
            "-PmcaceProductVersion=${project.version}",
        )
        arguments.addAll(modernFabricNestedExecutionArguments(gradle.startParameter.isOffline))
        sourceCommitProperty.orNull?.let { commit ->
            arguments.add("-PmcaceSourceCommit=$commit")
        }
        explicitClientBuildId.orNull?.let { buildId ->
            arguments.add("-PmcaceClientBuildId=$buildId")
        }
        val wrapper = layout.projectDirectory.file(if (windows) "gradlew.bat" else "gradlew")
            .asFile.absolutePath
        val command = if (windows) {
            mutableListOf(wrapper)
        } else {
            mutableListOf("bash", wrapper)
        }
        command.addAll(arguments)
        workingDir(layout.projectDirectory)
        environment("JAVA_HOME", javaHome.absolutePath)
        environment(
            "PATH",
            javaHome.resolve("bin").absolutePath + File.pathSeparator +
                System.getenv("PATH").orEmpty(),
        )
        commandLine(command)
    }
}

tasks.named<Delete>("clean") {
    // Root build/runtime-* and build/platform-smoke* contain hash-bound process
    // evidence and reviewed server caches.  A normal reproducible build must not
    // silently destroy those independent gate inputs.  Clean only outputs owned
    // by the root build itself; every Java subproject and fabric-modern still
    // receives its own clean task below/through Gradle task selection.
    setDelete(listOf(
        layout.buildDirectory.dir("release-bundle"),
        layout.buildDirectory.dir("local-verification-bundle"),
        layout.buildDirectory.dir("fabric-modern-deps"),
        layout.buildDirectory.dir("reports"),
    ))
    dependsOn(cleanModernFabric)
}
stageModernFabricDeps.configure {
    mustRunAfter(tasks.named("clean"))
}
tasks.named("build") {
    dependsOn(modernFabricBuild)
}

tasks.register<MCAceReleaseBundleTask>("releaseBundle") {
    group = "distribution"
    description = "Builds the six supported deployables as an exact eight-file release bundle."
    // Source identity and worktree cleanliness are live release assertions, not
    // properties that an earlier up-to-date result may safely stand in for.
    outputs.upToDateWhen { false }
    dependsOn(
        ":mcace-client-fabric:remapJar",
        modernFabricBuild,
        ":mcace-server-velocity:shadowJar",
        ":mcace-server-bungeecord:shadowJar",
        ":mcace-server-paper:shadowJar",
    )
    fabric12111Jar.set(project(":mcace-client-fabric").layout.buildDirectory.file(
        "libs/mcace-client-fabric-${project.version}.jar"))
    fabric2612Jar.set(modernFabric2612Jar)
    fabric262Jar.set(modernFabric262Jar)
    velocityJar.set(project(":mcace-server-velocity").layout.buildDirectory.file(
        "libs/mcace-server-velocity-${project.version}.jar"))
    bungeeJar.set(project(":mcace-server-bungeecord").layout.buildDirectory.file(
        "libs/mcace-server-bungeecord-${project.version}.jar"))
    paperJar.set(project(":mcace-server-paper").layout.buildDirectory.file(
        "libs/mcace-server-paper-${project.version}.jar"))
    sourceCommit.set(sourceCommitProperty.orElse("MISSING"))
    productVersion.set(version.toString())
    bundleProfile.set("RELEASE")
    fabric12111BuildId.set(
        sourceCommitProperty.map { commit -> "fabric-1.21.11-$commit" }.orElse("MISSING"))
    fabric2612BuildId.set(
        sourceCommitProperty.map { commit -> "fabric-26.1.2-$commit" }.orElse("MISSING"))
    fabric262BuildId.set(
        sourceCommitProperty.map { commit -> "fabric-26.2-$commit" }.orElse("MISSING"))
    rootJavaVersion.set(providers.systemProperty("java.version"))
    rootGradleVersion.set(GradleVersion.current().version)
    modernRuntimeIdentity.set(modernRuntimeIdentityFile)
    repositoryDirectory.set(layout.projectDirectory)
    outputDirectory.set(layout.buildDirectory.dir("release-bundle"))
}

tasks.register<MCAceReleaseBundleTask>("localVerificationBundle") {
    group = "verification"
    description =
        "Builds a non-release exact-eight-file bundle with an explicit LOCAL_UNSPECIFIED identity."
    outputs.upToDateWhen { false }
    dependsOn(
        ":mcace-client-fabric:remapJar",
        modernFabricBuild,
        ":mcace-server-velocity:shadowJar",
        ":mcace-server-bungeecord:shadowJar",
        ":mcace-server-paper:shadowJar",
    )
    fabric12111Jar.set(project(":mcace-client-fabric").layout.buildDirectory.file(
        "libs/mcace-client-fabric-${project.version}.jar"))
    fabric2612Jar.set(modernFabric2612Jar)
    fabric262Jar.set(modernFabric262Jar)
    velocityJar.set(project(":mcace-server-velocity").layout.buildDirectory.file(
        "libs/mcace-server-velocity-${project.version}.jar"))
    bungeeJar.set(project(":mcace-server-bungeecord").layout.buildDirectory.file(
        "libs/mcace-server-bungeecord-${project.version}.jar"))
    paperJar.set(project(":mcace-server-paper").layout.buildDirectory.file(
        "libs/mcace-server-paper-${project.version}.jar"))
    sourceCommit.set("LOCAL_UNSPECIFIED")
    productVersion.set(version.toString())
    bundleProfile.set("LOCAL_VERIFICATION")
    fabric12111BuildId.set(configuredFabric12111BuildId)
    fabric2612BuildId.set(configuredFabric2612BuildId)
    fabric262BuildId.set(configuredFabric262BuildId)
    rootJavaVersion.set(providers.systemProperty("java.version"))
    rootGradleVersion.set(GradleVersion.current().version)
    modernRuntimeIdentity.set(modernRuntimeIdentityFile)
    repositoryDirectory.set(layout.projectDirectory)
    outputDirectory.set(layout.buildDirectory.dir("local-verification-bundle"))
}

tasks.register("resolveAndLockAll") {
    group = "verification"
    description = "Resolves every subproject configuration for dependency lock/verification updates."
    notCompatibleWithConfigurationCache("Its dependency lock maintenance tasks are intentionally not cacheable.")
    dependsOn(subprojects.map { it.tasks.named("resolveAndLockAll") })
}
