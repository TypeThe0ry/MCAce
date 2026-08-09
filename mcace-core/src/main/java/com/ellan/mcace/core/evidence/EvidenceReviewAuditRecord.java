package com.ellan.mcace.core.evidence;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Content-free audit event for an opt-in local evidence review link. */
public record EvidenceReviewAuditRecord(
        UUID evidenceId, Instant occurredAt, String operatorId, String reason, Outcome outcome) {
    public EvidenceReviewAuditRecord {
        Objects.requireNonNull(evidenceId, "evidenceId");
        Objects.requireNonNull(occurredAt, "occurredAt");
        operatorId = bounded(operatorId, "operatorId", 128);
        reason = bounded(reason, "reason", 256);
        Objects.requireNonNull(outcome, "outcome");
    }

    private static String bounded(String value, String name, int maximum) {
        value = Objects.requireNonNull(value, name).strip();
        if (value.isEmpty() || value.length() > maximum || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("invalid " + name);
        }
        return value;
    }

    public enum Outcome {
        ISSUED,
        SERVED,
        EXPIRED,
        INVALID_ARTIFACT,
        UNAVAILABLE
    }
}
