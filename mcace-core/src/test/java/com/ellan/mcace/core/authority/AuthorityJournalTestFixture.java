package com.ellan.mcace.core.authority;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/** Test-only journal provisioning; production main sources intentionally have no creator. */
final class AuthorityJournalTestFixture {
    private AuthorityJournalTestFixture() {
    }

    static void initializeEmpty(Path path) throws IOException {
        Files.write(path, ServerAuthorityJournalPreflight.requiredInitialContentUtf8(),
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }
}
