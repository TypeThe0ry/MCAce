package com.ellan.mcace.core.federation;

/**
 * Audit boundary. A successful {@link #append(FederationAuditRecord)} must mean that the record is
 * durably committed according to the sink's storage contract. {@link #offer(FederationAuditRecord)}
 * only means that asynchronous telemetry was accepted for later handling and must never authorize
 * a federation state transition.
 */
@FunctionalInterface
public interface FederationAuditSink {
    void append(FederationAuditRecord record);

    /** Attempts to enqueue non-authorizing telemetry without promising a durable append. */
    default boolean offer(FederationAuditRecord record) {
        try {
            append(record);
            return true;
        } catch (RuntimeException exception) {
            return false;
        }
    }

    /** Content-free health used to fail federation closed after an asynchronous storage fault. */
    default FederationAuditHealth health() {
        return FederationAuditHealth.synchronousHealthy();
    }

    /**
     * Legacy factory name retained for source compatibility. It deliberately returns an
     * unavailable sink so an omitted production journal can never authorize federation.
     */
    @Deprecated(forRemoval = false)
    static FederationAuditSink noop() {
        return unavailable();
    }

    /** Explicit non-persistent boundary used only by a disabled fallback runtime. */
    static FederationAuditSink unavailable() {
        return new FederationAuditSink() {
            @Override public void append(FederationAuditRecord record) {
                throw new IllegalStateException("federation audit is unavailable");
            }

            @Override public boolean offer(FederationAuditRecord record) {
                return false;
            }

            @Override public FederationAuditHealth health() {
                return new FederationAuditHealth(false, 0, 0L, 1L);
            }
        };
    }
}
