package com.ellan.mcace.core.persistence;

import java.util.Objects;
import java.util.UUID;

public record AppealTransition(
        UUID appealId,
        long expectedVersion,
        AppealStatus targetStatus,
        String reason,
        String actorId) {
    public AppealTransition {
        Objects.requireNonNull(appealId, "appealId");
        Objects.requireNonNull(targetStatus, "targetStatus");
        reason = ReviewCaseDraft.requireText(reason, "reason", 4_096);
        actorId = ReviewCaseDraft.requireText(actorId, "actorId", 128);
        if (expectedVersion <= 0) throw new IllegalArgumentException("expectedVersion must be positive");
    }
}
