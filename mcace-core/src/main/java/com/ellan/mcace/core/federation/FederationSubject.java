package com.ellan.mcace.core.federation;

import com.ellan.mcace.protocol.ProtocolConstants;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Narrow immutable view of one locally authenticated session for federation binding. */
public record FederationSubject(
        UUID playerId,
        String localNetworkId,
        String authenticatedSessionId,
        PublicKey clientPublicKey,
        byte[] serverChallengeNonce,
        String policyVersion,
        byte[] policySha256,
        Instant authenticatedAt,
        Optional<FederationAuthenticationBinding> targetAuthenticationBinding) {
    public FederationSubject {
        Objects.requireNonNull(playerId, "playerId");
        FederationPeerPin.requireNetworkId(localNetworkId);
        requireText(authenticatedSessionId, "authenticatedSessionId");
        Objects.requireNonNull(clientPublicKey, "clientPublicKey");
        serverChallengeNonce = Objects.requireNonNull(serverChallengeNonce, "serverChallengeNonce").clone();
        policySha256 = Objects.requireNonNull(policySha256, "policySha256").clone();
        requireText(policyVersion, "policyVersion");
        Objects.requireNonNull(authenticatedAt, "authenticatedAt");
        targetAuthenticationBinding = Objects.requireNonNull(
                targetAuthenticationBinding, "targetAuthenticationBinding");
        if (serverChallengeNonce.length != ProtocolConstants.NONCE_BYTES || policySha256.length != 32) {
            throw new IllegalArgumentException("invalid federation subject digest/nonce length");
        }
    }

    /** Ordinary local authentication has no federation assertion transcript binding. */
    public FederationSubject(
            UUID playerId,
            String localNetworkId,
            String authenticatedSessionId,
            PublicKey clientPublicKey,
            byte[] serverChallengeNonce,
            String policyVersion,
            byte[] policySha256,
            Instant authenticatedAt) {
        this(playerId, localNetworkId, authenticatedSessionId, clientPublicKey,
                serverChallengeNonce, policyVersion, policySha256, authenticatedAt, Optional.empty());
    }

    @Override
    public byte[] serverChallengeNonce() {
        return serverChallengeNonce.clone();
    }

    @Override
    public byte[] policySha256() {
        return policySha256.clone();
    }

    private static void requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank() || value.length() > ProtocolConstants.MAX_FEDERATION_ID_CHARS
                || value.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("invalid " + name);
        }
    }
}
