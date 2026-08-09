package com.ellan.mcace.fabric;

import java.util.Objects;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;
import net.fabricmc.loader.api.metadata.CustomValue;

/** Release metadata embedded by Gradle and bound into the signed client hello. */
record FabricClientBuildMetadata(String clientVersion, String minecraftVersion, String buildId) {
    private static final String MCACE_MOD_ID = "mcace";
    private static final String MINECRAFT_MOD_ID = "minecraft";
    private static final String BUILD_ID_KEY = "mcace:client_build_id";

    FabricClientBuildMetadata {
        clientVersion = validate(clientVersion, "clientVersion");
        minecraftVersion = validate(minecraftVersion, "minecraftVersion");
        buildId = validate(buildId, "buildId");
    }

    static FabricClientBuildMetadata load(FabricLoader loader) {
        Objects.requireNonNull(loader, "loader");
        ModContainer mcace = loader.getModContainer(MCACE_MOD_ID)
                .orElseThrow(() -> new IllegalStateException("MCAce Fabric metadata is unavailable"));
        ModContainer minecraft = loader.getModContainer(MINECRAFT_MOD_ID)
                .orElseThrow(() -> new IllegalStateException("Minecraft Fabric metadata is unavailable"));
        CustomValue build = mcace.getMetadata().getCustomValue(BUILD_ID_KEY);
        if (build == null || build.getType() != CustomValue.CvType.STRING) {
            throw new IllegalStateException("MCAce client build ID is missing from fabric.mod.json");
        }
        return new FabricClientBuildMetadata(
                mcace.getMetadata().getVersion().getFriendlyString(),
                minecraft.getMetadata().getVersion().getFriendlyString(),
                build.getAsString());
    }

    private static String validate(String value, String name) {
        Objects.requireNonNull(value, name);
        String normalized = value.strip();
        if (normalized.isEmpty() || normalized.length() > 128
                || normalized.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(name + " must be 1-128 printable characters");
        }
        return normalized;
    }
}
