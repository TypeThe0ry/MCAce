plugins {
    id("com.gradleup.shadow") version "9.2.2"
}

dependencies {
    implementation(project(":mcace-core"))
    implementation(project(":mcace-sdk"))
    implementation(project(":mcace-storage-postgres"))
    compileOnly("com.velocitypowered:velocity-api:3.5.1")
    annotationProcessor("com.velocitypowered:velocity-api:3.5.1")
    testImplementation(project(":mcace-protocol"))
    testImplementation("com.velocitypowered:velocity-api:3.5.1")
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

tasks.withType<JavaCompile>().configureEach {
    // Velocity's processor intentionally handles @Plugin only; javac otherwise
    // reports the other runtime annotations as unclaimed under -Xlint:all.
    options.compilerArgs.add("-Xlint:-processing")
}
