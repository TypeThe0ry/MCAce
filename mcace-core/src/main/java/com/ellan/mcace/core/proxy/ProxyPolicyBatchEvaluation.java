package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.DispositionAction;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/** Bounded audit summary for a complete manifest; it never contains the raw manifest. */
public record ProxyPolicyBatchEvaluation(
        ProxyPolicyRefreshStatus refreshStatus,
        int totalObservations,
        Map<DispositionAction, Integer> actionCounts,
        DispositionAction highestAction,
        Optional<String> winningRuleId,
        Optional<String> activePolicyVersion,
        Optional<Long> activePolicySequence,
        Optional<Instant> activePolicyExpiresAt,
        int advisoryEnforcementRuleBlocks,
        List<ProxyPolicyEvaluation> retainedEvaluations,
        boolean truncated) {
    public ProxyPolicyBatchEvaluation {
        Objects.requireNonNull(refreshStatus, "refreshStatus");
        Objects.requireNonNull(actionCounts, "actionCounts");
        Objects.requireNonNull(highestAction, "highestAction");
        Objects.requireNonNull(winningRuleId, "winningRuleId");
        Objects.requireNonNull(activePolicyVersion, "activePolicyVersion");
        Objects.requireNonNull(activePolicySequence, "activePolicySequence");
        Objects.requireNonNull(activePolicyExpiresAt, "activePolicyExpiresAt");
        Objects.requireNonNull(retainedEvaluations, "retainedEvaluations");
        if (totalObservations < 0 || advisoryEnforcementRuleBlocks < 0
                || retainedEvaluations.size() > totalObservations) {
            throw new IllegalArgumentException("invalid proxy policy batch evaluation");
        }
        int countedObservations = 0;
        DispositionAction countedHighest = DispositionAction.OBSERVE;
        boolean hasCount = false;
        for (Map.Entry<DispositionAction, Integer> entry : actionCounts.entrySet()) {
            Objects.requireNonNull(entry.getKey(), "actionCounts key");
            Integer count = Objects.requireNonNull(entry.getValue(), "actionCounts value");
            if (count <= 0) {
                throw new IllegalArgumentException("action counts must be positive");
            }
            countedObservations = Math.addExact(countedObservations, count);
            if (!hasCount || entry.getKey().severity() > countedHighest.severity()) {
                countedHighest = entry.getKey();
                hasCount = true;
            }
        }
        if (countedObservations != totalObservations
                || (hasCount && highestAction != countedHighest)
                || (!hasCount && highestAction != DispositionAction.OBSERVE)) {
            throw new IllegalArgumentException("aggregate action summary is inconsistent");
        }
        boolean hasCompletePolicyIdentity = activePolicyVersion.isPresent()
                && activePolicySequence.isPresent() && activePolicyExpiresAt.isPresent();
        if (hasCompletePolicyIdentity != (activePolicyVersion.isPresent()
                || activePolicySequence.isPresent() || activePolicyExpiresAt.isPresent())) {
            throw new IllegalArgumentException("active policy identity must be complete or absent");
        }
        winningRuleId.ifPresent(value -> {
            if (value.isBlank() || value.length() > 128 || value.chars().anyMatch(Character::isISOControl)) {
                throw new IllegalArgumentException("winning rule id is invalid");
            }
        });
        actionCounts = Map.copyOf(actionCounts);
        retainedEvaluations = List.copyOf(retainedEvaluations);
    }
}
