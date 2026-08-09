package com.ellan.mcace.core.persistence;

import java.util.Objects;
import java.util.UUID;

public record AppealDraft(
        UUID appealId,
        UUID caseId,
        UUID playerId,
        String statement,
        String submittedBy) {
    public AppealDraft {
        Objects.requireNonNull(appealId, "appealId");
        Objects.requireNonNull(caseId, "caseId");
        Objects.requireNonNull(playerId, "playerId");
        statement = ReviewCaseDraft.requireText(statement, "statement", 8_192);
        submittedBy = ReviewCaseDraft.requireText(submittedBy, "submittedBy", 128);
    }
}
