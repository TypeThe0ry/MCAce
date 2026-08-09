package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class ProxyIdentityPinPathsTest {
    @TempDir Path temporaryDirectory;

    @Test
    void fallsBackToLegacyOnlyWhenPreferredPinIsAbsent() throws Exception {
        Path legacy = temporaryDirectory.resolve(ProxyIdentityPinPaths.LEGACY_FILE_NAME);
        Files.writeString(legacy, "legacy-key");

        ProxyIdentityPinPaths.Selection selected = ProxyIdentityPinPaths.select(temporaryDirectory);

        assertEquals(legacy.toAbsolutePath().normalize(), selected.path());
        assertTrue(selected.legacy());
    }

    @Test
    void malformedPreferredPinCannotFallBackToLegacyPin() throws Exception {
        Path legacy = temporaryDirectory.resolve(ProxyIdentityPinPaths.LEGACY_FILE_NAME);
        Path preferred = temporaryDirectory.resolve(ProxyIdentityPinPaths.PREFERRED_FILE_NAME);
        Files.writeString(legacy, "old-key");
        Files.writeString(preferred, "replacement-key");

        ProxyIdentityPinPaths.Selection selected = ProxyIdentityPinPaths.select(temporaryDirectory);

        assertEquals(preferred.toAbsolutePath().normalize(), selected.path());
        assertFalse(selected.legacy());
        assertThrows(IOException.class, () -> ProxyIdentityStore.load(selected.path()));
    }

    @Test
    void missingPinsStillProduceAPathThatFailsClosedWhenLoaded() {
        ProxyIdentityPinPaths.Selection selected = ProxyIdentityPinPaths.select(temporaryDirectory);

        assertEquals(temporaryDirectory.resolve(ProxyIdentityPinPaths.LEGACY_FILE_NAME)
                .toAbsolutePath().normalize(), selected.path());
        assertTrue(selected.legacy());
    }
}
