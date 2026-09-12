package com.ellan.mcace.core.federation;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.FederationLocalClaim;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Independent, in-memory OBSERVE summary for one target session.
 *
 * <p>This is not a local TrustLevel, admission status, risk reason, disposition, or punishment
 * recommendation. It expires with the signed assertion and is removed on target disconnect.</p>
 */
public record FederationObservation(
        UUID playerId,
        String targetAuthenticatedSessionId,
        String sourceNetworkId,
        String targetNetworkId,
        UUID assertionId,
        String sourcePolicyVersion,
        FederationLocalClaim remoteClaim,
        Instant issuedAt,
        Instant expiresAt,
        Instant observedAt) {
    public FederationObservation {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(targetAuthenticatedSessionId, "targetAuthenticatedSessionId");
        FederationPeerPin.requireNetworkId(sourceNetworkId);
        FederationPeerPin.requireNetworkId(targetNetworkId);
        Objects.requireNonNull(assertionId, "assertionId");
        Objects.requireNonNull(sourcePolicyVersion, "sourcePolicyVersion");
        Objects.requireNonNull(remoteClaim, "remoteClaim");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(observedAt, "observedAt");
        if (targetAuthenticatedSessionId.isBlank()
                || targetAuthenticatedSessionId.length() > ProtocolConstants.MAX_FEDERATION_ID_CHARS
                || targetAuthenticatedSessionId.codePoints().anyMatch(Character::isISOControl)
                || sourcePolicyVersion.isBlank()
                || sourcePolicyVersion.length() > ProtocolConstants.MAX_FEDERATION_ID_CHARS
                || sourcePolicyVersion.codePoints().anyMatch(Character::isISOControl)
                || !expiresAt.isAfter(issuedAt)
                || !observedAt.isBefore(expiresAt)) {
            throw new IllegalArgumentException("invalid federation observation");
        }
    }
}
