package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.disposition.DispositionAction;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class FileArtifactObservationAuditSinkTest {
    @TempDir Path directory;

    @Test void persistsOnlyContentFreeSummaryAndSupportsBoundedPlayerQuery() throws Exception {
        UUID player = UUID.randomUUID();
        Path journal = directory.resolve("dynamic-audit.log");
        FileArtifactObservationAuditSink sink = new FileArtifactObservationAuditSink(journal, 4096);
        sink.append(new ArtifactObservationAuditRecord(player, Instant.parse("2026-08-09T00:00:00Z"),
                Instant.parse("2026-08-09T00:00:01Z"), 2, 1,
                Map.of(DispositionAction.OBSERVE, 1, DispositionAction.WARN, 1), ProxyPolicyRefreshStatus.ACTIVE));

        assertEquals(1, sink.status().recordCount());
        assertTrue(sink.status().enabled());
        ArtifactObservationAuditRecord record = sink.recent(player, 1).getFirst();
        assertEquals(2, record.observationCount());
        assertEquals(1, record.consistencyIssueCount());
        String raw = Files.readString(journal);
        assertFalse(raw.contains("path"));
        assertFalse(raw.contains("filename"));
        assertFalse(raw.contains("sha256"));
        assertEquals(1, new FileArtifactObservationAuditSink(journal, 4096).recent(player, 1).size());
    }

    @Test void quotaDropsSummaryWithoutThrowingOrChangingAvailability() throws Exception {
        FileArtifactObservationAuditSink sink = new FileArtifactObservationAuditSink(directory.resolve("small.log"), 32);
        sink.append(new ArtifactObservationAuditRecord(UUID.randomUUID(), Instant.EPOCH, Instant.EPOCH,
                0, 0, Map.of(), ProxyPolicyRefreshStatus.ACTIVE));
        assertEquals(1, sink.status().droppedCount());
        assertEquals(0, sink.status().recordCount());
    }
}
