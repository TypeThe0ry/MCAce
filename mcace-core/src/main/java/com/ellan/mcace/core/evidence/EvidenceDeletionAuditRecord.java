package com.ellan.mcace.core.evidence;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Content-free administrative deletion audit. */
public record EvidenceDeletionAuditRecord(
        UUID evidenceId, Instant at, String operatorId, String reason, boolean deleted) {
    public EvidenceDeletionAuditRecord {
        Objects.requireNonNull(evidenceId, "evidenceId");
        Objects.requireNonNull(at, "at");
        operatorId = bounded(operatorId, "operatorId", 128);
        reason = bounded(reason, "reason", 256);
    }

    private static String bounded(String value, String name, int max) {
        Objects.requireNonNull(value, name);
        if (value.isBlank() || value.length() > max || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("invalid " + name);
        }
        return value;
    }
}
