pluginManagement {
    repositories {
        maven("https://maven.fabricmc.net/") {
            name = "fabric"
        }
        gradlePluginPortal()
    }
}

rootProject.name = "mcace-fabric-modern"

include("client-26.1.2", "client-26.2")
