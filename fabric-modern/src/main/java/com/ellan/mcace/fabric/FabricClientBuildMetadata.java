package com.ellan.mcace.fabric;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.CodeSource;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.regex.Pattern;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;
import net.fabricmc.loader.api.metadata.CustomValue;

/** Release metadata embedded by Gradle and bound into the signed client hello. */
record FabricClientBuildMetadata(String clientVersion, String minecraftVersion, String buildId) {
    private static final String MCACE_MOD_ID = "mcace";
    private static final String MINECRAFT_MOD_ID = "minecraft";
    private static final String BUILD_ID_KEY = "mcace:client_build_id";
    private static final Pattern MARKER_COMPONENT = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._+\\-]{0,127}");
    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");

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

    String artifactLoadedMarker() {
        return "MCACE_FABRIC_ARTIFACT_LOADED version=" + clientVersion + " build_id=" + buildId;
    }

    String artifactLoadedMarker(String codeSourceSha256) {
        return artifactLoadedMarker() + " code_source_sha256=" + validateSha256(codeSourceSha256, "codeSourceSha256");
    }

    static String verifiedCodeSourceSha256(Class<?> loadedClass, String expectedSha256) {
        String expected = validateSha256(expectedSha256, "expectedSha256");
        String actual = codeSourceSha256(loadedClass);
        if (!actual.equals(expected)) {
            throw new IllegalStateException(
                    "MCAce Fabric entrypoint CodeSource SHA-256 does not match the final Fabric JAR");
        }
        return actual;
    }

    static String codeSourceSha256(Class<?> loadedClass) {
        Objects.requireNonNull(loadedClass, "loadedClass");
        CodeSource codeSource = loadedClass.getProtectionDomain().getCodeSource();
        URL location = codeSource == null ? null : codeSource.getLocation();
        if (location == null || !"file".equalsIgnoreCase(location.getProtocol())) {
            throw new IllegalStateException("MCAce Fabric entrypoint has no local-file CodeSource");
        }
        try {
            Path origin = Path.of(location.toURI()).toRealPath();
            if (!Files.isRegularFile(origin)) {
                throw new IllegalStateException("MCAce Fabric entrypoint CodeSource is not a JAR file");
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = Files.newInputStream(origin)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    digest.update(buffer, 0, read);
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (IOException | URISyntaxException | NoSuchAlgorithmException exception) {
            throw new IllegalStateException("Could not hash the MCAce Fabric entrypoint CodeSource", exception);
        }
    }

    private static String validate(String value, String name) {
        Objects.requireNonNull(value, name);
        String normalized = value.strip();
        if (!MARKER_COMPONENT.matcher(normalized).matches()) {
            throw new IllegalArgumentException(name + " must be a safe 1-128 character marker component");
        }
        return normalized;
    }

    private static String validateSha256(String value, String name) {
        Objects.requireNonNull(value, name);
        String normalized = value.strip();
        if (!SHA256.matcher(normalized).matches()) {
            throw new IllegalArgumentException(name + " must be exactly 64 lowercase hex characters");
        }
        return normalized;
    }
}
