package com.ellan.mcace.core.persistence;

import com.ellan.mcace.core.risk.RiskPolicy;
import java.util.Objects;
import java.util.UUID;

public record RiskPolicyDeployment(
        RiskPolicy baseline,
        RiskPolicy candidate,
        UUID candidatePolicyId,
        UUID rolloutId,
        PolicyRolloutStage stage,
        int percentage) {
    public RiskPolicyDeployment {
        Objects.requireNonNull(baseline, "baseline");
        Objects.requireNonNull(stage, "stage");
        if (percentage < 0 || percentage > 100) throw new IllegalArgumentException("invalid percentage");
        if ((candidate == null) != (rolloutId == null) || (candidate == null) != (candidatePolicyId == null)) {
            throw new IllegalArgumentException("candidate, policy ID, and rollout ID must appear together");
        }
        if (candidate == null && stage != PolicyRolloutStage.BASELINE && stage != PolicyRolloutStage.FULL
                && stage != PolicyRolloutStage.PAUSED && stage != PolicyRolloutStage.ROLLED_BACK) {
            throw new IllegalArgumentException("deployment stage requires a candidate");
        }
    }

    public static RiskPolicyDeployment builtin() {
        return new RiskPolicyDeployment(
                RiskPolicy.defaults(), null, null, null, PolicyRolloutStage.BASELINE, 0);
    }
}
