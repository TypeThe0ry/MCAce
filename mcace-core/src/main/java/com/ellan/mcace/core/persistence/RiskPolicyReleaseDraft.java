package com.ellan.mcace.core.persistence;

import com.ellan.mcace.core.risk.RiskEventType;
import com.ellan.mcace.core.risk.RiskPolicy;
import java.util.Objects;
import java.util.UUID;

public record RiskPolicyReleaseDraft(
        UUID policyId,
        RiskPolicy policy,
        String description,
        String createdBy) {
    public RiskPolicyReleaseDraft {
        Objects.requireNonNull(policyId, "policyId");
        Objects.requireNonNull(policy, "policy");
        description = ReviewCaseDraft.requireText(description, "description", 1_024);
        createdBy = ReviewCaseDraft.requireText(createdBy, "createdBy", 128);
        if (!policy.version().matches("[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}")) {
            throw new IllegalArgumentException("policy version has an invalid format");
        }
        if (policy.version().equals(RiskPolicy.defaults().version())) {
            throw new IllegalArgumentException("the built-in baseline policy version is reserved");
        }
        if (!policy.weights().keySet().containsAll(java.util.Set.of(RiskEventType.values()))) {
            throw new IllegalArgumentException("policy must define every risk event weight");
        }
    }
}
