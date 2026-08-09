package com.ellan.mcace.core.persistence;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public record WebSessionHandoff(
        UUID handoffId,
        byte[] secretSha256,
        WebPrincipalType principalType,
        String subjectId,
        Set<WebRole> roles,
        String redirectPath,
        String createdBy,
        Instant createdAt,
        Instant expiresAt) {
    public WebSessionHandoff {
        Objects.requireNonNull(handoffId, "handoffId");
        secretSha256 = hash(secretSha256);
        Objects.requireNonNull(principalType, "principalType");
        subjectId = bounded(subjectId, "subjectId", 128);
        roles = Set.copyOf(Objects.requireNonNull(roles, "roles"));
        validateRoles(principalType, roles);
        redirectPath = redirect(redirectPath);
        createdBy = bounded(createdBy, "createdBy", 128);
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Duration lifetime = Duration.between(createdAt, expiresAt);
        if (lifetime.isZero() || lifetime.isNegative() || lifetime.compareTo(Duration.ofMinutes(10)) > 0) {
            throw new IllegalArgumentException("web handoff lifetime must be between 1 ms and 10 minutes");
        }
        if (principalType == WebPrincipalType.PLAYER) {
            UUID.fromString(subjectId);
        }
    }

    @Override public byte[] secretSha256() { return secretSha256.clone(); }

    static void validateRoles(WebPrincipalType principalType, Set<WebRole> roles) {
        if (roles.isEmpty()) {
            throw new IllegalArgumentException("web principal requires at least one role");
        }
        if (principalType == WebPrincipalType.PLAYER && !roles.equals(Set.of(WebRole.PLAYER))) {
            throw new IllegalArgumentException("player web principals may only hold PLAYER");
        }
        if (principalType == WebPrincipalType.OPERATOR
                && (roles.contains(WebRole.PLAYER) || !roles.contains(WebRole.OPERATOR_VIEWER))) {
            throw new IllegalArgumentException("operator web principals require OPERATOR_VIEWER and cannot hold PLAYER");
        }
    }

    private static byte[] hash(byte[] value) {
        Objects.requireNonNull(value, "secretSha256");
        if (value.length != 32) {
            throw new IllegalArgumentException("secretSha256 must contain 32 bytes");
        }
        return value.clone();
    }

    static String bounded(String value, String field, int maximum) {
        Objects.requireNonNull(value, field);
        String normalized = value.strip();
        if (normalized.isEmpty() || normalized.length() > maximum
                || normalized.chars().anyMatch(character -> character < 0x20 || character == 0x7f)) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return normalized;
    }

    private static String redirect(String value) {
        String normalized = bounded(value, "redirectPath", 128);
        if (!normalized.startsWith("/") || normalized.startsWith("//")
                || normalized.contains("\\") || normalized.contains("?") || normalized.contains("#")) {
            throw new IllegalArgumentException("redirectPath must be a local path without query or fragment");
        }
        return normalized;
    }
}
