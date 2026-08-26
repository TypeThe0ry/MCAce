plugins {
    id("com.gradleup.shadow") version "9.2.2"
}

repositories {
    maven("https://hub.spigotmc.org/nexus/repository/public/") {
        name = "spigotmc"
        content {
            includeGroup("net.md-5")
        }
    }
}

dependencies {
    implementation(project(":mcace-core"))
    implementation(project(":mcace-sdk"))
    testImplementation(project(":mcace-client-common"))
    testImplementation(project(":mcace-protocol"))
    // Build 2028 and later expose PlayerConfigurationEvent on the 1.21-R0.5 API line.
    compileOnly("net.md-5:bungeecord-api:1.21-R0.5-SNAPSHOT")
    testImplementation("net.md-5:bungeecord-api:1.21-R0.5-SNAPSHOT")
}

tasks.shadowJar {
    archiveClassifier.set("")
    relocate("com.google.protobuf", "com.ellan.mcace.internal.protobuf")
}

tasks.jar {
    archiveClassifier.set("plain")
}

tasks.test {
    systemProperty("java.io.tmpdir", temporaryDir.absolutePath)
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
