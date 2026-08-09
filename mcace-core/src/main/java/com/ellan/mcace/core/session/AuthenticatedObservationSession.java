package com.ellan.mcace.core.session;

import java.security.PublicKey;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Narrow, immutable verification view for post-authentication observation transport. */
public record AuthenticatedObservationSession(
        UUID playerId, String sessionId, PublicKey clientPublicKey, Instant expiresAt) {
    public AuthenticatedObservationSession {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(clientPublicKey, "clientPublicKey");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (sessionId.isBlank()) {
            throw new IllegalArgumentException("sessionId must not be blank");
        }
    }
}
