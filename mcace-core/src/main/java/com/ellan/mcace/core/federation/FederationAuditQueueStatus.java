package com.ellan.mcace.core.federation;

/** Content-free health counters for the bounded federation audit worker. */
public record FederationAuditQueueStatus(
        int capacity,
        int queued,
        long accepted,
        long processed,
        long saturated,
        long handlerFailures,
        long rejectedAfterClose,
        boolean closed,
        boolean workerAlive) {
    public FederationAuditQueueStatus {
        if (capacity <= 0 || queued < 0 || queued > capacity || accepted < 0L || processed < 0L
                || saturated < 0L || handlerFailures < 0L || rejectedAfterClose < 0L) {
            throw new IllegalArgumentException("invalid federation audit queue status");
        }
    }
}
