package com.ellan.mcace.core.persistence;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.core.risk.RiskEventType;
import com.ellan.mcace.core.risk.RiskPolicy;
import java.util.EnumMap;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class RiskPolicyReleaseTest {
    @Test
    void releaseHashIsDeterministicAndRequiresCompleteWeights() {
        RiskPolicyReleaseDraft draft = new RiskPolicyReleaseDraft(
                UUID.randomUUID(), policy("phase3-canary-1"), "controlled fixture", "policy-operator");
        assertArrayEquals(RiskPolicyReleaseCodec.hash(draft), RiskPolicyReleaseCodec.hash(draft));
        assertThrows(IllegalArgumentException.class, () -> new RiskPolicyReleaseDraft(
                UUID.randomUUID(), new RiskPolicy(
                        "incomplete-policy", java.util.Map.of(RiskEventType.UNKNOWN_MOD, 20), 20, 50, 80),
                "invalid fixture", "policy-operator"));
    }

    @Test
    void rolloutStagesEnforceSafePercentages() {
        UUID policyId = UUID.randomUUID();
        assertThrows(IllegalArgumentException.class, () -> new PolicyRolloutDraft(
                UUID.randomUUID(), policyId, PolicyRolloutStage.SHADOW, 1,
                "shadow cannot assign players", "policy-operator"));
        assertThrows(IllegalArgumentException.class, () -> new PolicyRolloutDraft(
                UUID.randomUUID(), policyId, PolicyRolloutStage.CANARY, 50,
                "canary is deliberately bounded", "policy-operator"));
    }

    private static RiskPolicy policy(String version) {
        EnumMap<RiskEventType, Integer> weights = new EnumMap<>(RiskEventType.class);
        for (RiskEventType type : RiskEventType.values()) weights.put(type, 10);
        return new RiskPolicy(version, weights, 20, 50, 80);
    }
}
