package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class FabricClientBuildMetadataTest {
    @Test
    void validatesReleaseMetadataBeforeItEntersSignedHello() {
        FabricClientBuildMetadata metadata = new FabricClientBuildMetadata(
                "0.1.0-SNAPSHOT", "1.21.1", "fabric-release-17");

        assertEquals("0.1.0-SNAPSHOT", metadata.clientVersion());
        assertEquals("1.21.1", metadata.minecraftVersion());
        assertEquals("fabric-release-17", metadata.buildId());
        assertThrows(IllegalArgumentException.class,
                () -> new FabricClientBuildMetadata("0.1.0", "1.21.1", "bad\nbuild"));
    }

    @Test
    void processedFabricMetadataContainsExplicitBuildIdentity() throws Exception {
        try (InputStream input = FabricClientBuildMetadataTest.class.getResourceAsStream("/fabric.mod.json")) {
            assertTrue(input != null, "processed fabric.mod.json missing");
            String json = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            assertTrue(json.contains("\"version\": \"0.1.0-SNAPSHOT\""));
            assertTrue(json.contains("\"mcace:client_build_id\": \"fabric-phase2-dev\""));
            assertFalse(json.contains("${mcace_"));
        }
    }
}
