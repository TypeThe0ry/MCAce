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
        byte[] signedAssertionSha256,
        long issuedAtEpochMs,
        long sourceAuthorizedAtEpochMs,
        long expiresAtEpochMs,
        long verifiedAtEpochMs,
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
        signedAssertionSha256 = Objects.requireNonNull(
                signedAssertionSha256, "signedAssertionSha256").clone();
        if (signedAssertionSha256.length != 32) {
            throw new IllegalArgumentException("signedAssertionSha256 must be SHA-256");
        }
        if (issuedAtEpochMs <= 0L || sourceAuthorizedAtEpochMs < issuedAtEpochMs
                || sourceAuthorizedAtEpochMs >= expiresAtEpochMs
                || verifiedAtEpochMs <= 0L || verifiedAtEpochMs >= expiresAtEpochMs) {
            throw new IllegalArgumentException("invalid federation verification timeline");
        }
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

    @Override
    public byte[] signedAssertionSha256() {
        return signedAssertionSha256.clone();
    }
}
