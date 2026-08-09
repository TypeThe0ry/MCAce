plugins {
    application
}

dependencies {
    implementation(project(":mcace-protocol"))
}

application {
    mainClass.set("com.ellan.mcace.launcher.MCAceLauncherMain")
}
