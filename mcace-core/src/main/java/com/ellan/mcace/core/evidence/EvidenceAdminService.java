package com.ellan.mcace.core.evidence;

import java.time.Clock;
import java.util.Objects;
import java.util.UUID;

/** Administrator-facing store controls. Responses contain only bounded metadata. */
public final class EvidenceAdminService {
    private final EvidenceStoreControl store;
    private final EvidenceAuditSink auditSink;
    private final Clock clock;

    public EvidenceAdminService(EvidenceStoreControl store, EvidenceAuditSink auditSink, Clock clock) {
        this.store = Objects.requireNonNull(store, "store");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public EvidenceStoreStatus status() { return store.status(); }

    public boolean delete(UUID evidenceId, String reason, String operatorId) throws Exception {
        Objects.requireNonNull(evidenceId, "evidenceId");
        boolean deleted;
        try {
            deleted = store.delete(evidenceId);
        } catch (Exception failure) {
            auditSink.appendDeletion(new EvidenceDeletionAuditRecord(
                    evidenceId, clock.instant(), operatorId, reason, false));
            throw failure;
        }
        auditSink.appendDeletion(new EvidenceDeletionAuditRecord(
                evidenceId, clock.instant(), operatorId, reason, deleted));
        return deleted;
    }

    public int sweepExpired(int maxDeletes) throws Exception {
        return store.sweepExpired(maxDeletes);
    }

    public static EvidenceAdminService disabled(Clock clock, EvidenceAuditSink auditSink) {
        return new EvidenceAdminService(new EvidenceStoreControl() {
            @Override public EvidenceStoreStatus status() {
                return EvidenceStoreStatus.disabled("DISABLED_DEFAULT_DISCARD");
            }
            @Override public boolean delete(UUID ignored) { return false; }
            @Override public int sweepExpired(int ignored) { return 0; }
        }, auditSink, clock);
    }
}
