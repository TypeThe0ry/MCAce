package com.ellan.mcace.core.persistence;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public record StoredWebSession(
        UUID sessionId,
        byte[] secretSha256,
        WebPrincipalType principalType,
        String subjectId,
        Set<WebRole> roles,
        String createdBy,
        Instant createdAt,
        Instant expiresAt) {
    public StoredWebSession {
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(secretSha256, "secretSha256");
        if (secretSha256.length != 32) {
            throw new IllegalArgumentException("secretSha256 must contain 32 bytes");
        }
        secretSha256 = secretSha256.clone();
        Objects.requireNonNull(principalType, "principalType");
        subjectId = WebSessionHandoff.bounded(subjectId, "subjectId", 128);
        roles = Set.copyOf(Objects.requireNonNull(roles, "roles"));
        WebSessionHandoff.validateRoles(principalType, roles);
        createdBy = WebSessionHandoff.bounded(createdBy, "createdBy", 128);
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Duration lifetime = Duration.between(createdAt, expiresAt);
        if (lifetime.isZero() || lifetime.isNegative() || lifetime.compareTo(Duration.ofHours(12)) > 0) {
            throw new IllegalArgumentException("web session lifetime must be between 1 ms and 12 hours");
        }
        if (principalType == WebPrincipalType.PLAYER) {
            UUID.fromString(subjectId);
        }
    }

    @Override public byte[] secretSha256() { return secretSha256.clone(); }

    public boolean permits(WebRole role) {
        return roles.contains(role);
    }
}
