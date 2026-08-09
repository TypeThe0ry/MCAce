package com.ellan.mcace.core.federation;

/** Bounded, content-free runtime status for administrative commands. */
public record FederationRuntimeState(
        boolean enabled,
        String localNetworkId,
        int pinnedPeers,
        int pendingConsentRequests,
        int activeObservations) {
    public FederationRuntimeState {
        if (pinnedPeers < 0 || pendingConsentRequests < 0 || activeObservations < 0) {
            throw new IllegalArgumentException("negative federation runtime count");
        }
    }
}
