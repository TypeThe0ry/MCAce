plugins {
    id("com.gradleup.shadow") version "9.2.2"
    application
}

dependencies {
    implementation(project(":mcace-core"))
    implementation(project(":mcace-protocol"))
    implementation(project(":mcace-storage-postgres"))
    implementation("com.fasterxml.jackson.core:jackson-databind:2.21.5")

    testImplementation(platform("org.testcontainers:testcontainers-bom:2.0.5"))
    testImplementation("org.testcontainers:testcontainers-junit-jupiter")
    testImplementation("org.testcontainers:testcontainers-postgresql")
}

application {
    mainClass.set("com.ellan.mcace.cloud.MCAceCloudMain")
}

tasks.shadowJar {
    archiveClassifier.set("")
    mergeServiceFiles()
}

tasks.jar {
    archiveClassifier.set("plain")
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
