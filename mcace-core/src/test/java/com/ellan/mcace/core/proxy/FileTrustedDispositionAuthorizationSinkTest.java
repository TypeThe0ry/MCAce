package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class FileTrustedDispositionAuthorizationSinkTest {
    @TempDir Path directory;

    @Test
    void persistsOnlyContentFreeAuthorizationMetadata() throws Exception {
        Path journal = directory.resolve("trusted-disposition-authorizations.log");
        FileTrustedDispositionAuthorizationSink sink =
                new FileTrustedDispositionAuthorizationSink(journal, 4096);
        sink.append(record());

        List<String> lines = Files.readAllLines(journal);
        assertEquals(1, lines.size());
        String raw = lines.getFirst();
        String[] columns = raw.split("\\t", -1);
        assertEquals(16, columns.length);
        assertEquals("v3", columns[0]);
        assertEquals("00000000-0000-0000-0000-000000000010", columns[1]);
        assertEquals("00000000-0000-0000-0000-000000000001", columns[2]);
        assertEquals(Long.toString(Instant.parse("2026-08-12T00:00:00Z").toEpochMilli()),
                columns[3]);
        assertEquals("11".repeat(32), columns[4]);
        assertEquals("22".repeat(32), columns[5]);
        assertEquals("33".repeat(32), columns[6]);
        assertEquals("ADMIN_REVIEWED", columns[7]);
        assertEquals("console", columns[8]);
        assertEquals("CASE-42", columns[9]);
        assertEquals("QUARANTINE", columns[10]);
        assertEquals("reviewed-rule", columns[11]);
        assertEquals("ACTIVE", columns[12]);
        assertEquals("policy-1", columns[13]);
        assertEquals("1", columns[14]);
        assertEquals(Long.toString(Instant.parse("2026-08-12T00:05:00Z").toEpochMilli()),
                columns[15]);
        assertFalse(raw.contains("example.mod"));
        assertFalse(raw.contains("00".repeat(32)));
        assertFalse(raw.contains("path"));
    }

    @Test
    void quotaFailureIsVisibleAndFailClosed() throws Exception {
        FileTrustedDispositionAuthorizationSink sink =
                new FileTrustedDispositionAuthorizationSink(directory.resolve("small.log"), 32);
        assertThrows(IOException.class, () -> sink.append(record()));
    }

    private static TrustedDispositionAuthorizationRecord record() {
        return new TrustedDispositionAuthorizationRecord(
                UUID.fromString("00000000-0000-0000-0000-000000000010"),
                UUID.fromString("00000000-0000-0000-0000-000000000001"),
                Instant.parse("2026-08-12T00:00:00Z"), "11".repeat(32), "22".repeat(32),
                "33".repeat(32),
                ObservationOrigin.ADMIN_REVIEWED,
                Optional.of("console"), Optional.of("CASE-42"), DispositionAction.QUARANTINE,
                Optional.of("reviewed-rule"), ProxyPolicyRefreshStatus.ACTIVE,
                Optional.of("policy-1"), Optional.of(1L),
                Optional.of(Instant.parse("2026-08-12T00:05:00Z")));
    }
}
