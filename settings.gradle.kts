pluginManagement {
    repositories {
        maven("https://maven.fabricmc.net/") {
            name = "fabric"
        }
        gradlePluginPortal()
    }
}

rootProject.name = "MCAce"

include(
    "mcace-protocol",
    "mcace-sdk",
    "mcace-core",
    "mcace-storage-postgres",
    "mcace-cloud",
    "mcace-cloud-client",
    "mcace-launcher",
    "mcace-runtime-integration",
    "mcace-client-common",
    "mcace-client-fabric",
    "mcace-server-velocity",
    "mcace-server-bungeecord",
    "mcace-server-paper",
)
