package com.ellan.mcace.core.proxy;

import java.util.List;
import java.util.UUID;

/** Read-only administrative surface for content-free dynamic observation summaries. */
public interface ArtifactObservationAuditSink {
    void append(ArtifactObservationAuditRecord record);
    ArtifactObservationAuditStatus status();
    List<ArtifactObservationAuditRecord> recent(UUID playerId, int limit);
    static ArtifactObservationAuditSink noop() {
        return new ArtifactObservationAuditSink() {
            @Override public void append(ArtifactObservationAuditRecord ignored) { }
            @Override public ArtifactObservationAuditStatus status() { return ArtifactObservationAuditStatus.disabled(); }
            @Override public List<ArtifactObservationAuditRecord> recent(UUID ignored, int limit) { return List.of(); }
        };
    }
}
