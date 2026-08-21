package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class FabricClientBuildMetadataTest {
    @Test
    void validatesReleaseMetadataBeforeItEntersSignedHello() {
        FabricClientBuildMetadata metadata = new FabricClientBuildMetadata(
                "0.1.0-SNAPSHOT", "26.2", "fabric-26.2-release-17");

        assertEquals("0.1.0-SNAPSHOT", metadata.clientVersion());
        assertEquals("26.2", metadata.minecraftVersion());
        assertEquals("fabric-26.2-release-17", metadata.buildId());
        assertEquals(
                "MCACE_FABRIC_ARTIFACT_LOADED version=0.1.0-SNAPSHOT build_id=fabric-26.2-release-17",
                metadata.artifactLoadedMarker());
        String sha256 = "0123456789abcdef".repeat(4);
        assertEquals(
                "MCACE_FABRIC_ARTIFACT_LOADED version=0.1.0-SNAPSHOT build_id=fabric-26.2-release-17"
                        + " code_source_sha256=" + sha256,
                metadata.artifactLoadedMarker(sha256));
        assertThrows(IllegalArgumentException.class,
                () -> new FabricClientBuildMetadata("0.1.0", "26.2", "bad\nbuild"));
        assertThrows(IllegalArgumentException.class,
                () -> new FabricClientBuildMetadata("0.1.0", "26.2", "bad build"));
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
    void processedFabricMetadataContainsTheExactModernTargetAndBuildIdentity() {
        ModernFabricTestTarget.Target target = ModernFabricTestTarget.current();
        String json = target.metadata();

        assertEquals("0.1.0-SNAPSHOT", ModernFabricTestTarget.jsonString(json, "version"));
        assertEquals(target.minecraftVersion(), ModernFabricTestTarget.jsonString(json, "minecraft"));
        assertEquals(target.fabricApiVersion(), ModernFabricTestTarget.jsonString(json, "fabric-api"));
        assertEquals(">=25", ModernFabricTestTarget.jsonString(json, "java"));
        assertEquals(target.buildId(), ModernFabricTestTarget.jsonString(json, "mcace:client_build_id"));
        assertFalse(json.contains("${"), json);
    }
}

final class FabricCodeSourceProbe {}
