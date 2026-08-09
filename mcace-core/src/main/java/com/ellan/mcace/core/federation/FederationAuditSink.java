package com.ellan.mcace.core.federation;

/**
 * Audit boundary. Production proxy adapters should supply a bounded non-blocking implementation;
 * the direct {@link #append(FederationAuditRecord)} method remains for simple in-memory tests and
 * the single-worker delegate.
 */
@FunctionalInterface
public interface FederationAuditSink {
    void append(FederationAuditRecord record);

    /**
     * Attempts to accept one immutable audit summary without prescribing durable-I/O semantics.
     * Synchronous sinks retain their historical behavior; bounded asynchronous sinks override
     * this method so proxy plugin-message threads never wait for disk I/O.
     */
    default boolean offer(FederationAuditRecord record) {
        try {
            append(record);
            return true;
        } catch (RuntimeException exception) {
            return false;
        }
    }

    static FederationAuditSink noop() {
        return ignored -> { };
    }
}
