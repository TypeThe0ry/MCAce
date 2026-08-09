plugins {
    id("net.fabricmc.fabric-loom-remap") version "1.14.10"
}

repositories {
    maven("https://maven.fabricmc.net/") {
        name = "fabric"
    }
}

dependencies {
    minecraft("com.mojang:minecraft:1.21.1")
    mappings("net.fabricmc:yarn:1.21.1+build.3:v2")
    modImplementation("net.fabricmc:fabric-loader:0.19.3")
    modImplementation("net.fabricmc.fabric-api:fabric-api:0.116.15+1.21.1")
    implementation(project(":mcace-client-common"))
    include(project(":mcace-client-common"))
    include(project(":mcace-protocol"))
    include("com.google.protobuf:protobuf-java:4.32.1")
}

val mcaceClientBuildId = providers.gradleProperty("mcaceClientBuildId")
    .getOrElse("fabric-phase2-dev")
val mcaceVersion = version.toString()

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
