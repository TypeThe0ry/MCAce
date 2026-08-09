package com.ellan.mcace.core.federation;

import java.util.Objects;
import java.util.Set;

/** Content-free administrative view; the public key itself is never returned. */
public record FederationPeerSummary(
        String networkId,
        String keyIdSha256Hex,
        Set<FederationPeerCapability> capabilities) {
    public FederationPeerSummary {
        FederationPeerPin.requireNetworkId(networkId);
        Objects.requireNonNull(keyIdSha256Hex, "keyIdSha256Hex");
        if (!keyIdSha256Hex.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("invalid federation peer summary key id");
        }
        capabilities = Set.copyOf(Objects.requireNonNull(capabilities, "capabilities"));
        if (capabilities.isEmpty()) {
            throw new IllegalArgumentException("federation peer summary capabilities are empty");
        }
    }
}
