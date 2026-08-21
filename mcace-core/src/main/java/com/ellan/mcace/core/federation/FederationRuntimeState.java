package com.ellan.mcace.core.federation;

/** Bounded, content-free runtime status for administrative commands. */
public record FederationRuntimeState(
        boolean enabled,
        boolean configuredEnabled,
        boolean auditHealthy,
        String localNetworkId,
        int pinnedPeers,
        int pendingConsentRequests,
        int activeObservations,
        int auditBacklog,
        long auditCommitted,
        long auditFailures) {
    public FederationRuntimeState {
        if (enabled && (!configuredEnabled || !auditHealthy)) {
            throw new IllegalArgumentException("enabled federation requires configuration and audit health");
        }
        if (pinnedPeers < 0 || pendingConsentRequests < 0 || activeObservations < 0
                || auditBacklog < 0 || auditCommitted < 0L || auditFailures < 0L) {
            throw new IllegalArgumentException("negative federation runtime count");
        }
    }
}
