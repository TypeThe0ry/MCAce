package com.ellan.mcace.core.persistence;

import java.util.Objects;
import java.util.UUID;

public record PolicyRolloutDraft(
        UUID rolloutId,
        UUID policyId,
        PolicyRolloutStage stage,
        int percentage,
        String reason,
        String createdBy) {
    public PolicyRolloutDraft {
        Objects.requireNonNull(rolloutId, "rolloutId");
        Objects.requireNonNull(policyId, "policyId");
        Objects.requireNonNull(stage, "stage");
        reason = ReviewCaseDraft.requireText(reason, "reason", 4_096);
        createdBy = ReviewCaseDraft.requireText(createdBy, "createdBy", 128);
        boolean valid = switch (stage) {
            case SHADOW, PAUSED, ROLLED_BACK -> percentage == 0;
            case CANARY -> percentage >= 1 && percentage <= 25;
            case BROAD -> percentage >= 26 && percentage <= 99;
            case FULL -> percentage == 100;
            case BASELINE -> false;
        };
        if (!valid) throw new IllegalArgumentException("invalid rollout percentage for stage");
    }
}
