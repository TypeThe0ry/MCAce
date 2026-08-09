package com.ellan.mcace.core.evidence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.FileSystemException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.io.TempDir;

final class EvidenceReviewEndpointConfigurationTest {
    @TempDir Path temporaryDirectory;

    @Test
    void createsSafeLoopbackOnlyDefaults() throws Exception {
        EvidenceReviewEndpointConfiguration configuration = EvidenceReviewEndpointConfiguration.loadOrCreate(
                temporaryDirectory.resolve(EvidenceReviewEndpointConfiguration.FILE_NAME));

        assertFalse(configuration.enabled());
        assertEquals("127.0.0.1", configuration.bindAddress());
        assertEquals(0, configuration.port());
        assertEquals(60, configuration.tokenTtlSeconds());
        assertEquals(16, configuration.maxTokens());
    }

    @Test
    void rejectsNonLoopbackAndOutOfBoundValues() throws Exception {
        Path config = temporaryDirectory.resolve(EvidenceReviewEndpointConfiguration.FILE_NAME);
        Files.writeString(config, "enabled=true\nbind=0.0.0.0\nport=8080\ntoken-ttl-seconds=60\nmax-tokens=16\n");
        assertThrows(IOException.class, () -> EvidenceReviewEndpointConfiguration.loadOrCreate(config));

        Files.writeString(config, "enabled=true\nbind=127.0.0.1\nport=70000\ntoken-ttl-seconds=9\nmax-tokens=129\n");
        assertThrows(IOException.class, () -> EvidenceReviewEndpointConfiguration.loadOrCreate(config));
    }

    @Test
    void rejectsOversizedAndSymbolicLinkConfigurations() throws Exception {
        Path config = temporaryDirectory.resolve(EvidenceReviewEndpointConfiguration.FILE_NAME);
        Files.writeString(config, "#" + "x".repeat(64 * 1024));
        assertThrows(IOException.class, () -> EvidenceReviewEndpointConfiguration.loadOrCreate(config));

        Path target = temporaryDirectory.resolve("review-target.properties");
        Files.writeString(target, "enabled=false\n");
        Path link = temporaryDirectory.resolve("review-link.properties");
        try {
            Files.createSymbolicLink(link, target.getFileName());
        } catch (UnsupportedOperationException | FileSystemException exception) {
            Assumptions.assumeTrue(false, "symbolic links are unavailable on this test host");
        }
        assertThrows(IOException.class, () -> EvidenceReviewEndpointConfiguration.loadOrCreate(link));
    }

    @Test
    void rejectsUnknownAndDuplicateKeysRatherThanSelectingOneSilently() throws Exception {
        Path config = temporaryDirectory.resolve(EvidenceReviewEndpointConfiguration.FILE_NAME);
        Files.writeString(config, "enabled=false\nunknown=true\n");
        assertThrows(IOException.class, () -> EvidenceReviewEndpointConfiguration.loadOrCreate(config));

        Files.writeString(config, "enabled=false\nenabled=true\n");
        assertThrows(IOException.class, () -> EvidenceReviewEndpointConfiguration.loadOrCreate(config));
    }
}
