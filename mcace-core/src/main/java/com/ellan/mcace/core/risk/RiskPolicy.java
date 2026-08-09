package com.ellan.mcace.core.risk;

import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;

public record RiskPolicy(
        String version,
        Map<RiskEventType, Integer> weights,
        int watchThreshold,
        int restrictedThreshold,
        int investigationThreshold) {
    public RiskPolicy {
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(weights, "weights");
        if (version.isBlank()) {
            throw new IllegalArgumentException("version must not be blank");
        }
        EnumMap<RiskEventType, Integer> copy = new EnumMap<>(RiskEventType.class);
        copy.putAll(weights);
        if (copy.values().stream().anyMatch(weight -> weight < 0)) {
            throw new IllegalArgumentException("weights must not be negative");
        }
        if (watchThreshold < 0 || restrictedThreshold <= watchThreshold
                || investigationThreshold <= restrictedThreshold) {
            throw new IllegalArgumentException("risk thresholds must be strictly increasing");
        }
        weights = Map.copyOf(copy);
    }

    public static RiskPolicy defaults() {
        return new RiskPolicy(
                "phase1-v1",
                Map.of(
                        RiskEventType.MISSING_MCACE, 20,
                        RiskEventType.UNKNOWN_MOD, 15,
                        RiskEventType.MANIFEST_MISMATCH, 50,
                        RiskEventType.AUTH_REPLAY, 100,
                        RiskEventType.AGENT_UNAVAILABLE, 40,
                        RiskEventType.EVIDENCE_ANOMALY, 30,
                        RiskEventType.BEHAVIOR_HIGH_RISK, 60,
                        RiskEventType.POLICY_MISMATCH, 50,
                        RiskEventType.PROTOCOL_VIOLATION, 80),
                20,
                50,
                80);
    }
}
