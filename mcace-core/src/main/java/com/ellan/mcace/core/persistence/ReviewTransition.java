package com.ellan.mcace.core.persistence;

import java.util.Objects;
import java.util.UUID;

public record ReviewTransition(
        UUID caseId,
        long expectedVersion,
        ReviewStatus targetStatus,
        String reason,
        String recommendation,
        String actorId) {
    public ReviewTransition {
        Objects.requireNonNull(caseId, "caseId");
        Objects.requireNonNull(targetStatus, "targetStatus");
        reason = ReviewCaseDraft.requireText(reason, "reason", 4_096);
        recommendation = Objects.requireNonNull(recommendation, "recommendation");
        actorId = ReviewCaseDraft.requireText(actorId, "actorId", 128);
        if (expectedVersion <= 0 || recommendation.length() > 1_024) {
            throw new IllegalArgumentException("invalid review transition");
        }
        if (targetStatus == ReviewStatus.ACTION_RECOMMENDED && recommendation.isBlank()) {
            throw new IllegalArgumentException("recommendation is required for ACTION_RECOMMENDED");
        }
    }
}
