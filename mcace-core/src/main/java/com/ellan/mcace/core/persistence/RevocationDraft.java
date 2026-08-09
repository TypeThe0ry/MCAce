package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record RevocationDraft(
        UUID revocationId,
        RevocationSubjectType subjectType,
        String subjectId,
        String reasonCode,
        Instant effectiveAt,
        Instant expiresAt,
        String actorId) {
    public RevocationDraft {
        Objects.requireNonNull(revocationId, "revocationId");
        Objects.requireNonNull(subjectType, "subjectType");
        subjectId = requireText(subjectId, "subjectId", 256);
        reasonCode = requireText(reasonCode, "reasonCode", 64);
        Objects.requireNonNull(effectiveAt, "effectiveAt");
        actorId = requireText(actorId, "actorId", 128);
        if (expiresAt != null && !expiresAt.isAfter(effectiveAt)) {
            throw new IllegalArgumentException("revocation expiry must follow its effective time");
        }
    }

    private static String requireText(String value, String field, int maximumLength) {
        Objects.requireNonNull(value, field);
        if (value.isBlank() || value.length() > maximumLength) {
            throw new IllegalArgumentException(field + " is blank or too long");
        }
        return value;
    }
}
