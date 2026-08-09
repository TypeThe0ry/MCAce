package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record RiskPolicyEvaluation(
        UUID eventId,
        String appliedPolicyVersion,
        String baselinePolicyVersion,
        String candidatePolicyVersion,
        int assignedWeight,
        int baselineWeight,
        Integer candidateWeight,
        UUID rolloutId,
        PolicyRolloutStage stage,
        int cohortBucket,
        Instant evaluatedAt) {
    public RiskPolicyEvaluation {
        Objects.requireNonNull(eventId, "eventId");
        appliedPolicyVersion = ReviewCaseDraft.requireText(
                appliedPolicyVersion, "appliedPolicyVersion", 64);
        baselinePolicyVersion = ReviewCaseDraft.requireText(
                baselinePolicyVersion, "baselinePolicyVersion", 64);
        candidatePolicyVersion = Objects.requireNonNull(candidatePolicyVersion, "candidatePolicyVersion");
        Objects.requireNonNull(stage, "stage");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        if (assignedWeight < 0 || baselineWeight < 0 || candidatePolicyVersion.length() > 64
                || (candidateWeight != null && candidateWeight < 0)
                || cohortBucket < 0 || cohortBucket > 9_999) {
            throw new IllegalArgumentException("invalid risk policy evaluation");
        }
        if ((candidateWeight == null) != candidatePolicyVersion.isEmpty()
                || (rolloutId == null) != candidatePolicyVersion.isEmpty()) {
            throw new IllegalArgumentException("candidate evaluation fields are inconsistent");
        }
    }
}
