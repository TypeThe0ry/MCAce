plugins {
    id("com.gradleup.shadow") version "9.2.2"
}

val mcaceProductVersion = project.version.toString()

val generateMCAcePluginVersionSource = tasks.register<Copy>("generateMCAcePluginVersionSource") {
    val destination = layout.buildDirectory.dir("generated/sources/mcacePluginVersion")
    outputs.dir(destination)
    inputs.property("mcaceProductVersion", mcaceProductVersion)
    from(layout.projectDirectory.dir("src/main/templates"))
    into(destination)
    filter(
        org.apache.tools.ant.filters.ReplaceTokens::class,
        mapOf("tokens" to mapOf("mcaceVersion" to mcaceProductVersion)),
    )
}

sourceSets {
    named("main") {
        java.srcDir(generateMCAcePluginVersionSource)
    }
}

tasks.withType<JavaCompile>().configureEach {
    dependsOn(generateMCAcePluginVersionSource)
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
