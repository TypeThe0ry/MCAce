plugins {
    id("com.gradleup.shadow") version "9.2.2"
}

dependencies {
    implementation(project(":mcace-core"))
    implementation(project(":mcace-sdk"))
    testImplementation(project(":mcace-protocol"))
    compileOnly("net.md-5:bungeecord-api:1.21-R0.4")
    testImplementation("net.md-5:bungeecord-api:1.21-R0.4")
}

tasks.shadowJar {
    archiveClassifier.set("")
    relocate("com.google.protobuf", "com.ellan.mcace.internal.protobuf")
}

tasks.jar {
    archiveClassifier.set("plain")
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
