package com.ellan.mcace.fabric;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/** Shared target discovery for the identical 26.1.2 and 26.2 test source set. */
final class ModernFabricTestTarget {
    static final String DEPLOYABLE_JAR_PROPERTY = "mcace.fabric.deployable-jar";
    static final String MINECRAFT_VERSION_PROPERTY = "mcace.fabric.minecraft-version";
    static final String FABRIC_API_VERSION_PROPERTY = "mcace.fabric.fabric-api-version";
    static final String BUILD_ID_PROPERTY = "mcace.fabric.client-build-id";
    private static final Map<String, String> SUPPORTED_TARGETS = Map.of(
            "26.1.2", "0.155.2+26.1.2",
            "26.2", "0.157.0+26.2");
    private static final Pattern SAFE_MARKER =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9._+\\-]{0,127}");

    private ModernFabricTestTarget() {}

    static Target current() {
        String metadata = processedMetadata();
        String minecraftVersion = jsonString(metadata, "minecraft");
        String fabricApiVersion = jsonString(metadata, "fabric-api");
        String javaVersion = jsonString(metadata, "java");
        String buildId = jsonString(metadata, "mcace:client_build_id");
        String expectedFabricApi = SUPPORTED_TARGETS.get(minecraftVersion);
        if (expectedFabricApi == null) {
            throw new IllegalStateException("unsupported processed Minecraft target " + minecraftVersion);
        }
        if (!expectedFabricApi.equals(fabricApiVersion)) {
            throw new IllegalStateException(
                    "Fabric API does not match Minecraft " + minecraftVersion + ": " + fabricApiVersion);
        }
        if (!">=25".equals(javaVersion)) {
            throw new IllegalStateException("modern Fabric metadata must require Java >=25: " + javaVersion);
        }
        if (!SAFE_MARKER.matcher(buildId).matches()) {
            throw new IllegalStateException("processed build ID is not a safe marker: " + buildId);
        }
        requireConfiguredProperty(MINECRAFT_VERSION_PROPERTY, minecraftVersion);
        requireConfiguredProperty(FABRIC_API_VERSION_PROPERTY, fabricApiVersion);
        requireConfiguredProperty(BUILD_ID_PROPERTY, buildId);
        return new Target(minecraftVersion, fabricApiVersion, javaVersion, buildId, metadata);
    }

    static Path deployableJar(Target target) {
        Objects.requireNonNull(target, "target");
        String configured = System.getProperty(DEPLOYABLE_JAR_PROPERTY, "").strip();
        Path artifact;
        if (!configured.isEmpty()) {
            artifact = Path.of(configured);
        } else {
            Path libraryDirectory = Path.of("build", "libs").toAbsolutePath().normalize();
            String expectedPrefix = "mcace-client-fabric-" + target.minecraftVersion() + "-";
            try (Stream<Path> files = Files.isDirectory(libraryDirectory)
                    ? Files.list(libraryDirectory) : Stream.empty()) {
                List<Path> matches = files
                        .filter(Files::isRegularFile)
                        .filter(path -> {
                            String name = path.getFileName().toString();
                            return name.startsWith(expectedPrefix) && name.endsWith(".jar");
                        })
                        .toList();
                if (matches.size() != 1) {
                    throw new IllegalStateException(
                            DEPLOYABLE_JAR_PROPERTY + " is unset and expected exactly one "
                                    + expectedPrefix + "*.jar under " + libraryDirectory + "; got " + matches);
                }
                artifact = matches.getFirst();
            } catch (IOException exception) {
                throw new IllegalStateException("could not discover deployable modern Fabric JAR", exception);
            }
        }
        Path normalized = artifact.toAbsolutePath().normalize();
        if (!Files.isRegularFile(normalized)) {
            throw new IllegalStateException("deployable modern Fabric JAR is missing: " + normalized);
        }
        String fileName = normalized.getFileName().toString();
        if (!fileName.startsWith("mcace-client-fabric-" + target.minecraftVersion() + "-")
                || !fileName.endsWith(".jar")) {
            throw new IllegalStateException(
                    "deployable artifact name is not target-specific: " + fileName);
        }
        return normalized;
    }

    static String processedMetadata() {
        try (InputStream input = ModernFabricTestTarget.class.getResourceAsStream("/fabric.mod.json")) {
            if (input == null) {
                throw new IllegalStateException("processed fabric.mod.json is missing from the test runtime");
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException exception) {
            throw new IllegalStateException("could not read processed fabric.mod.json", exception);
        }
    }

    static String jsonString(String json, String key) {
        Pattern pattern = Pattern.compile(
                "\\\"" + Pattern.quote(key) + "\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"");
        Matcher matcher = pattern.matcher(json);
        if (!matcher.find()) {
            throw new IllegalStateException("missing JSON string " + key);
        }
        String value = unescapeJsonString(matcher.group(1));
        if (matcher.find()) {
            throw new IllegalStateException("duplicate JSON string " + key);
        }
        return value;
    }

    private static String unescapeJsonString(String encoded) {
        StringBuilder decoded = new StringBuilder(encoded.length());
        for (int index = 0; index < encoded.length(); index++) {
            char current = encoded.charAt(index);
            if (current != '\\') {
                decoded.append(current);
                continue;
            }
            if (++index >= encoded.length()) {
                throw new IllegalStateException("truncated JSON escape");
            }
            char escaped = encoded.charAt(index);
            switch (escaped) {
                case '\"', '\\', '/' -> decoded.append(escaped);
                case 'b' -> decoded.append('\b');
                case 'f' -> decoded.append('\f');
                case 'n' -> decoded.append('\n');
                case 'r' -> decoded.append('\r');
                case 't' -> decoded.append('\t');
                case 'u' -> {
                    if (index + 4 >= encoded.length()) {
                        throw new IllegalStateException("truncated JSON Unicode escape");
                    }
                    String hexadecimal = encoded.substring(index + 1, index + 5);
                    try {
                        decoded.append((char) Integer.parseInt(hexadecimal, 16));
                    } catch (NumberFormatException exception) {
                        throw new IllegalStateException(
                                "invalid JSON Unicode escape " + hexadecimal, exception);
                    }
                    index += 4;
                }
                default -> throw new IllegalStateException("unsupported JSON escape \\" + escaped);
            }
        }
        return decoded.toString();
    }

    private static void requireConfiguredProperty(String property, String actual) {
        String expected = System.getProperty(property, "").strip();
        if (expected.isEmpty()) {
            throw new IllegalStateException(property + " was not configured by Gradle");
        }
        if (!expected.equals(actual)) {
            throw new IllegalStateException(
                    property + " does not match processed metadata; expected=" + expected + " actual=" + actual);
        }
    }

    record Target(String minecraftVersion, String fabricApiVersion, String javaVersion,
            String buildId, String metadata) {}
}
