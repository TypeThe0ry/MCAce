package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record OperatorAuditRecord(
        UUID auditId,
        String actorId,
        String action,
        String targetType,
        String targetId,
        Instant occurredAt,
        String detailsJson) {
    public OperatorAuditRecord {
        Objects.requireNonNull(auditId, "auditId");
        actorId = requireText(actorId, "actorId", 128);
        action = requireText(action, "action", 64);
        targetType = requireText(targetType, "targetType", 64);
        targetId = requireText(targetId, "targetId", 256);
        Objects.requireNonNull(occurredAt, "occurredAt");
        detailsJson = requireText(detailsJson, "detailsJson", 16_384);
    }

    private static String requireText(String value, String field, int maximumLength) {
        Objects.requireNonNull(value, field);
        if (value.isBlank() || value.length() > maximumLength) {
            throw new IllegalArgumentException(field + " is blank or too long");
        }
        return value;
    }
}
