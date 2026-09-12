package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class FabricClientBuildMetadataTest {
    private static final String BUILD_ID_PROPERTY = "mcace.fabric.client-build-id";
    private static final String PRODUCT_VERSION_PROPERTY = "mcace.test.product-version";

    private static String productVersion() {
        return System.getProperty(PRODUCT_VERSION_PROPERTY, "0.1.0-SNAPSHOT");
    }

    @Test
    void validatesReleaseMetadataBeforeItEntersSignedHello() {
        FabricClientBuildMetadata metadata = new FabricClientBuildMetadata(
                productVersion(), "1.21.1", "fabric-release-17");

        assertEquals(productVersion(), metadata.clientVersion());
        assertEquals("1.21.1", metadata.minecraftVersion());
        assertEquals("fabric-release-17", metadata.buildId());
        assertEquals(
                "MCACE_FABRIC_ARTIFACT_LOADED version=" + productVersion()
                        + " build_id=fabric-release-17",
                metadata.artifactLoadedMarker());
        String sha256 = "0123456789abcdef".repeat(4);
        assertEquals(
                "MCACE_FABRIC_ARTIFACT_LOADED version=" + productVersion()
                        + " build_id=fabric-release-17"
                        + " code_source_sha256=" + sha256,
                metadata.artifactLoadedMarker(sha256));
        assertThrows(IllegalArgumentException.class,
                () -> new FabricClientBuildMetadata("0.1.0", "1.21.1", "bad\nbuild"));
        assertThrows(IllegalArgumentException.class,
                () -> new FabricClientBuildMetadata("0.1.0", "1.21.1", "bad build"));
        assertThrows(IllegalArgumentException.class, () -> metadata.artifactLoadedMarker("A".repeat(64)));
    }

    @Test
    void hashesAndVerifiesTheJarThatDefinedTheLoadedClass(@TempDir Path temporaryDirectory) throws Exception {
        String probeName = FabricCodeSourceProbe.class.getName();
        String probeEntry = probeName.replace('.', '/') + ".class";
        Path probeJar = temporaryDirectory.resolve("origin-probe.jar");
        try (InputStream input = FabricCodeSourceProbe.class.getClassLoader().getResourceAsStream(probeEntry);
                JarOutputStream output = new JarOutputStream(Files.newOutputStream(probeJar))) {
            assertTrue(input != null, "compiled CodeSource probe class missing");
            output.putNextEntry(new JarEntry(probeEntry));
            input.transferTo(output);
            output.closeEntry();
        }
        String expectedSha256 = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(probeJar)));

        try (URLClassLoader loader = new URLClassLoader(
                new java.net.URL[] {probeJar.toUri().toURL()}, null)) {
            Class<?> loadedProbe = Class.forName(probeName, true, loader);
            assertEquals(expectedSha256, FabricClientBuildMetadata.codeSourceSha256(loadedProbe));
            assertEquals(expectedSha256,
                    FabricClientBuildMetadata.verifiedCodeSourceSha256(loadedProbe, expectedSha256));
            assertThrows(IllegalStateException.class,
                    () -> FabricClientBuildMetadata.verifiedCodeSourceSha256(loadedProbe, "0".repeat(64)));
        }
    }

    @Test
    void processedFabricMetadataContainsExplicitBuildIdentity() throws Exception {
        try (InputStream input = FabricClientBuildMetadataTest.class.getResourceAsStream("/fabric.mod.json")) {
            assertTrue(input != null, "processed fabric.mod.json missing");
            String json = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            String expectedBuildId = System.getProperty(BUILD_ID_PROPERTY, "").strip();
            assertFalse(expectedBuildId.isEmpty(), BUILD_ID_PROPERTY + " was not configured by Gradle");
            assertTrue(json.contains("\"version\": \"" + productVersion() + "\""));
            assertTrue(json.contains("\"mcace:client_build_id\": \"" + expectedBuildId + "\""));
            assertFalse(json.contains("${mcace_"));
        }
    }
}

final class FabricCodeSourceProbe {}
