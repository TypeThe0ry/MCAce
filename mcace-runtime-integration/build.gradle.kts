import org.gradle.api.tasks.bundling.Jar
import org.gradle.api.tasks.compile.JavaCompile

val velocityObserver = sourceSets.create("velocityObserver")
val paperAdmissionObserver = sourceSets.create("paperAdmissionObserver")

dependencies {
    implementation(project(":mcace-core"))
    implementation(project(":mcace-client-common"))
    add(velocityObserver.compileOnlyConfigurationName, "com.velocitypowered:velocity-api:3.5.1")
    add(velocityObserver.annotationProcessorConfigurationName, "com.velocitypowered:velocity-api:3.5.1")
    add(paperAdmissionObserver.compileOnlyConfigurationName, project(":mcace-sdk"))
    add(paperAdmissionObserver.compileOnlyConfigurationName,
        "io.papermc.paper:paper-api:1.21.1-R0.1-SNAPSHOT")
}

val velocityObserverJar = tasks.register<Jar>("velocityObserverJar") {
    archiveFileName.set("mcace-runtime-velocity-observer-test-only.jar")
    from(velocityObserver.output)
}

val paperAdmissionObserverJar = tasks.register<Jar>("paperAdmissionObserverJar") {
    archiveFileName.set("mcace-runtime-paper-admission-observer-test-only.jar")
    from(paperAdmissionObserver.output)
}

tasks.named<JavaCompile>(velocityObserver.compileJavaTaskName) {
    // Velocity's processor owns @Plugin, while @Subscribe is consumed at runtime.
    options.compilerArgs.add("-Xlint:-processing")
}

tasks.test {
    dependsOn(
        ":mcace-server-velocity:shadowJar",
        ":mcace-server-bungeecord:shadowJar",
        ":mcace-server-paper:shadowJar",
        velocityObserverJar,
        paperAdmissionObserverJar,
    )
    systemProperty(
        "mcace.runtime.velocity-observer.jar",
        layout.buildDirectory.file("libs/mcace-runtime-velocity-observer-test-only.jar")
            .get().asFile.absolutePath,
    )
    systemProperty("mcace.runtime.classpath", sourceSets.main.get().runtimeClasspath.asPath)
    listOf(
        "mcace.folia.player-probe.host",
        "mcace.folia.player-probe.port",
        "mcace.folia.player-probe.minecraft-version",
        "mcace.folia.player-probe.private-key-path",
        "mcace.folia.player-probe.report-path",
        "mcace.folia.player-probe.hold-millis",
        "mcace.admission-probe.mode",
        "mcace.runtime.player-probe.enabled",
        "mcace.runtime.folia-context.enabled",
        "mcace.runtime.backend-kind",
        "mcace.runtime.backend.jar",
        "mcace.runtime.backend.jar.sha256",
        "mcace.runtime.backend.prepared-root",
        "mcace.runtime.backend.prepared-root.sha256",
        "mcace.runtime.minecraft-version",
        "mcace.runtime.minecraft-protocol",
        "mcace.runtime.server-java",
        "mcace.runtime.server-java.sha256",
        "mcace.runtime.server-java-feature",
        "mcace.runtime.velocity.jar",
        "mcace.runtime.velocity.jar.sha256",
        "mcace.runtime.bungee.jar",
        "mcace.runtime.bungee.jar.sha256",
        "mcace.runtime.folia.jar",
        "mcace.runtime.folia.prepared-root",
        "mcace.runtime.folia.minecraft-version",
        "mcace.runtime.federation.enabled",
        "mcace.runtime.federation.restart.enabled",
        "mcace.runtime.disposition.enabled",
        "mcace.runtime.trusted-disposition.enabled",
    ).forEach { key ->
        System.getProperty(key)?.let { value -> systemProperty(key, value) }
    }
}
