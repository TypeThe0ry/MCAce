package com.ellan.mcace.core.evidence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class EvidenceAdminServiceTest {
    @Test
    void deleteAuditsOneBoundedFinalResult() throws Exception {
        UUID id = UUID.randomUUID();
        List<EvidenceDeletionAuditRecord> audits = new ArrayList<>();
        EvidenceStoreControl control = new EvidenceStoreControl() {
            @Override public EvidenceStoreStatus status() { return EvidenceStoreStatus.disabled("TEST"); }
            @Override public boolean delete(UUID evidenceId) { return evidenceId.equals(id); }
            @Override public int sweepExpired(int maxDeletes) { return 0; }
        };
        EvidenceAuditSink sink = new EvidenceAuditSink() {
            @Override public void append(EvidenceAuditRecord ignored) { }
            @Override public void appendDeletion(EvidenceDeletionAuditRecord record) { audits.add(record); }
        };
        EvidenceAdminService admin = new EvidenceAdminService(
                control, sink, Clock.fixed(Instant.EPOCH, ZoneOffset.UTC));
        assertTrue(admin.delete(id, "case review", "velocity-console"));
        assertFalse(admin.delete(UUID.randomUUID(), "case review", "velocity-console"));
        assertEquals(2, audits.size());
        assertTrue(audits.getFirst().deleted());
        assertFalse(audits.getLast().deleted());
        assertThrows(IllegalArgumentException.class, () -> admin.delete(id, "bad\nreason", "operator"));
    }
}
