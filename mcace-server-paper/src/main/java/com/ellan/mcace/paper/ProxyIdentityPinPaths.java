package com.ellan.mcace.paper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Selects the pinned proxy identity without silently falling back from a present preferred pin.
 *
 * <p>The legacy filename is solely a migration path. If an operator has created the preferred
 * pin, even a malformed preferred file must be loaded (and consequently fail closed) rather than
 * allowing an older key to keep authorizing snapshots.</p>
 */
final class ProxyIdentityPinPaths {
    static final String PREFERRED_FILE_NAME = "proxy-public-key.txt";
    static final String LEGACY_FILE_NAME = "velocity-public-key.txt";

    private ProxyIdentityPinPaths() {
    }

    static Selection select(Path dataDirectory) {
        Path directory = Objects.requireNonNull(dataDirectory, "dataDirectory").toAbsolutePath().normalize();
        Path preferred = directory.resolve(PREFERRED_FILE_NAME);
        Path legacy = directory.resolve(LEGACY_FILE_NAME);
        return Files.isRegularFile(preferred)
                ? new Selection(preferred, false)
                : new Selection(legacy, true);
    }

    record Selection(Path path, boolean legacy) {
        Selection {
            path = Objects.requireNonNull(path, "path");
        }
    }
}
