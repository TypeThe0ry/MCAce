package com.ellan.mcace.core.proxy;

/** Content-free health and capacity status; it never exposes a local filesystem path. */
public record ArtifactObservationAuditStatus(
        boolean enabled, long recordCount, long storedBytes, long maxBytes, long droppedCount, long failureCount) {
    public ArtifactObservationAuditStatus {
        if (recordCount < 0 || storedBytes < 0 || maxBytes < 0 || droppedCount < 0 || failureCount < 0) {
            throw new IllegalArgumentException("invalid artifact observation audit status");
        }
    }
    public static ArtifactObservationAuditStatus disabled() { return new ArtifactObservationAuditStatus(false, 0, 0, 0, 0, 0); }
}
