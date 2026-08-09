package com.ellan.mcace.client.integrity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class ScopedIntegrityScannerTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void producesStableRootIndependentOfCreationOrder() throws Exception {
        Path mods = Files.createDirectories(temporaryDirectory.resolve("mods"));
        Files.writeString(mods.resolve("z.jar"), "z");
        Files.writeString(mods.resolve("a.jar"), "a");
        ScopedIntegrityScanner scanner = new ScopedIntegrityScanner(Clock.systemUTC());

        IntegrityManifest first = scanner.scan(temporaryDirectory, Path.of("mods"), ScanPolicy.mods());
        IntegrityManifest second = scanner.scan(temporaryDirectory, Path.of("mods"), ScanPolicy.mods());

        assertEquals(first.rootSha256Hex(), second.rootSha256Hex());
        assertEquals("a.jar", first.entries().getFirst().relativePath());
    }

    @Test
    void rejectsScopeEscape() {
        ScopedIntegrityScanner scanner = new ScopedIntegrityScanner(Clock.systemUTC());
        assertThrows(
                IntegrityScanException.class,
                () -> scanner.scan(temporaryDirectory, Path.of(".."), ScanPolicy.mods()));
    }
}
