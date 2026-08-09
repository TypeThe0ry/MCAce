package com.ellan.mcace.core.persistence;

import java.util.Objects;
import java.util.UUID;

public record ReviewCaseDraft(
        UUID caseId,
        UUID playerId,
        String title,
        String reason,
        String createdBy) {
    public ReviewCaseDraft {
        Objects.requireNonNull(caseId, "caseId");
        Objects.requireNonNull(playerId, "playerId");
        title = requireText(title, "title", 128);
        reason = requireText(reason, "reason", 4_096);
        createdBy = requireText(createdBy, "createdBy", 128);
    }

    static String requireText(String value, String field, int maximumLength) {
        Objects.requireNonNull(value, field);
        if (value.isBlank() || value.length() > maximumLength) {
            throw new IllegalArgumentException(field + " is blank or too long");
        }
        return value;
    }
}
