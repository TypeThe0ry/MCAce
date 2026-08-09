package com.ellan.mcace.core.session;

import com.ellan.mcace.protocol.generated.AuthRequest;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Already signature-verified AuthRequest material. It is an observation input, never authority. */
public record AuthenticatedManifest(
        UUID playerId, String sessionId, SecurityPolicy policy, AuthRequest request, Instant authenticatedAt) {
    public AuthenticatedManifest {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(authenticatedAt, "authenticatedAt");
        if (sessionId.isBlank()) throw new IllegalArgumentException("sessionId must not be blank");
    }
}
