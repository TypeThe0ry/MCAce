package com.ellan.mcace.core.federation;

import com.ellan.mcace.protocol.ProtocolConstants;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Content-free federation audit summary.
 *
 * <p>It deliberately contains no session id, challenge, public key, policy hash, manifest,
 * evidence, IP address, risk reason, admission state, or raw presentation.</p>
 */
public record FederationAuditRecord(
        Instant recordedAt,
        FederationAuditEvent event,
        FederationAuditOutcome outcome,
        String operatorId,
        UUID playerId,
        String sourceNetworkId,
        String targetNetworkId,
        Optional<UUID> assertionId,
        Optional<String> peerKeyFingerprint) {
    /** A short correlator, not the complete configured SHA-256 pin. */
    public static final int PEER_KEY_FINGERPRINT_HEX_CHARS = 16;

    public FederationAuditRecord {
        Objects.requireNonNull(recordedAt, "recordedAt");
        Objects.requireNonNull(event, "event");
        Objects.requireNonNull(outcome, "outcome");
        operatorId = bounded(operatorId, "operatorId", ProtocolConstants.MAX_FEDERATION_ID_CHARS);
        Objects.requireNonNull(playerId, "playerId");
        FederationPeerPin.requireNetworkId(sourceNetworkId);
        FederationPeerPin.requireNetworkId(targetNetworkId);
        assertionId = Objects.requireNonNull(assertionId, "assertionId");
        peerKeyFingerprint = Objects.requireNonNull(peerKeyFingerprint, "peerKeyFingerprint");
        if (peerKeyFingerprint.isPresent() && !peerKeyFingerprint.orElseThrow().matches(
                "[0-9a-f]{" + PEER_KEY_FINGERPRINT_HEX_CHARS + "}")) {
            throw new IllegalArgumentException("invalid federation peer key fingerprint");
        }
    }

    private static String bounded(String value, String name, int maximum) {
        Objects.requireNonNull(value, name);
        if (value.isBlank() || value.length() > maximum
                || value.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("invalid " + name);
        }
        return value;
    }
}
