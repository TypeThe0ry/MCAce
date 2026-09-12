plugins {
    id("com.gradleup.shadow") version "9.2.2"
}

dependencies {
    implementation(project(":mcace-core"))
    implementation(project(":mcace-cloud-client"))
    implementation(project(":mcace-sdk"))
    compileOnly("ac.grim.grimac:GrimAPI:1.6.0.9")
    compileOnly("io.papermc.paper:paper-api:1.21.1-R0.1-SNAPSHOT")
    testImplementation("io.papermc.paper:paper-api:1.21.1-R0.1-SNAPSHOT")
}

repositories {
    maven("https://repo.grim.ac/snapshots") {
        name = "grimacSnapshots"
        content { includeGroup("ac.grim.grimac") }
    }
}

tasks.shadowJar {
    archiveClassifier.set("")
    relocate("com.google.protobuf", "com.ellan.mcace.internal.protobuf")
    relocate("com.fasterxml.jackson", "com.ellan.mcace.internal.jackson")
}

val mcaceProductVersion = project.version.toString()

tasks.processResources {
    inputs.property("mcaceProductVersion", mcaceProductVersion)
    filter(
        org.apache.tools.ant.filters.ReplaceTokens::class,
        mapOf("tokens" to mapOf("mcaceVersion" to mcaceProductVersion)),
    )
}

tasks.jar {
    archiveClassifier.set("plain")
}

tasks.test {
    listOf(
        "mcace.vulcan.compatibility.enabled",
        "mcace.vulcan.compatibility.jar",
        "mcace.vulcan.compatibility.report",
    ).forEach { key ->
        System.getProperty(key)?.let { value -> systemProperty(key, value) }
    }
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
