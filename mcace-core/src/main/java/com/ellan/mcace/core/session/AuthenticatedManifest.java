package com.ellan.mcace.core.session;

import com.ellan.mcace.protocol.generated.AuthRequest;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Already signature-verified AuthRequest material, never independent cheating authority.
 * The legacy authenticatedAt field is client observation time for dynamic updates;
 * receivedAt is server acceptance time and observationSequence is zero for initial auth.
 * Receipt identity is internal metadata, not additional signed client evidence.
 */
public record AuthenticatedManifest(
        UUID playerId, String sessionId, SecurityPolicy policy, AuthRequest request, Instant authenticatedAt,
        long observationSequence, Instant receivedAt) {
    /** Compatibility for callers without a coordinator receipt; not an execution credential. */
    public AuthenticatedManifest(UUID playerId, String sessionId, SecurityPolicy policy,
            AuthRequest request, Instant authenticatedAt) {
        this(playerId, sessionId, policy, request, authenticatedAt, 0L, authenticatedAt);
    }

    public AuthenticatedManifest {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(authenticatedAt, "authenticatedAt");
        Objects.requireNonNull(receivedAt, "receivedAt");
        if (observationSequence < 0) throw new IllegalArgumentException("observationSequence must be nonnegative");
        if (sessionId.isBlank()) throw new IllegalArgumentException("sessionId must not be blank");
    }
}
