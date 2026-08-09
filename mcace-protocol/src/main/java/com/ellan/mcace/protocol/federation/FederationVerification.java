package com.ellan.mcace.protocol.federation;

import com.ellan.mcace.protocol.generated.FederationLocalClaim;
import java.util.Objects;

/**
 * Minimal verified remote statement. Deliberately does not expose or imply a local
 * MCAce TrustLevel; the target must keep its own admission and review semantics.
 */
public record FederationVerification(
        String sourceNetworkId,
        String targetNetworkId,
        String playerUuid,
        byte[] clientPublicKeySha256,
        String sourceAuthenticatedSessionId,
        String assertionId,
        long issuedAtEpochMs,
        long expiresAtEpochMs,
        String policyVersion,
        byte[] policySha256,
        String disclosure,
        FederationLocalClaim remoteClaim) {

    public FederationVerification {
        Objects.requireNonNull(sourceNetworkId, "sourceNetworkId");
        Objects.requireNonNull(targetNetworkId, "targetNetworkId");
        Objects.requireNonNull(playerUuid, "playerUuid");
        clientPublicKeySha256 = Objects.requireNonNull(clientPublicKeySha256, "clientPublicKeySha256").clone();
        Objects.requireNonNull(sourceAuthenticatedSessionId, "sourceAuthenticatedSessionId");
        Objects.requireNonNull(assertionId, "assertionId");
        Objects.requireNonNull(policyVersion, "policyVersion");
        policySha256 = Objects.requireNonNull(policySha256, "policySha256").clone();
        Objects.requireNonNull(disclosure, "disclosure");
        Objects.requireNonNull(remoteClaim, "remoteClaim");
    }

    @Override
    public byte[] clientPublicKeySha256() {
        return clientPublicKeySha256.clone();
    }

    @Override
    public byte[] policySha256() {
        return policySha256.clone();
    }
}
