package com.ellan.mcace.core.authority;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;

/** Read-only operational check for an operator-preprovisioned authority journal. */
public final class ServerAuthorityJournalPreflight {
    private ServerAuthorityJournalPreflight() {
    }

    /** Exact header line, without the required trailing LF byte. */
    public static String requiredHeaderLine() {
        return FileServerAuthorityIssuanceJournal.requiredHeaderLine();
    }

    /** Exact initial UTF-8 file bytes: the fixed header followed by one LF byte. */
    public static byte[] requiredInitialContentUtf8() {
        return FileServerAuthorityIssuanceJournal.requiredInitialContentUtf8();
    }

    /** Maximum supported bounded journal quota. */
    public static long maximumQuotaBytes() {
        return FileServerAuthorityIssuanceJournal.MAX_QUOTA_BYTES;
    }

    /**
     * Opens, locks, verifies and closes an existing journal without modifying it.
     * The file and every ancestor must already exist; this method never creates either.
     */
    public static void verify(Path preprovisionedJournal, long journalQuotaBytes)
            throws IOException {
        try (FileServerAuthorityIssuanceJournal journal =
                     new FileServerAuthorityIssuanceJournal(
                             Objects.requireNonNull(
                                     preprovisionedJournal, "preprovisionedJournal"),
                             journalQuotaBytes)) {
            // Exercise the same verified read path used by recovery without modifying state.
            journal.lastSequence("0".repeat(64));
        }
    }
}
