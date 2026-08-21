package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.DispositionAction;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Bounded audit summary for a complete manifest; it never contains the raw manifest. */
public record ProxyPolicyBatchEvaluation(
        ProxyPolicyRefreshStatus refreshStatus,
        int totalObservations,
        Map<DispositionAction, Integer> actionCounts,
        int advisoryEnforcementRuleBlocks,
        List<ProxyPolicyEvaluation> retainedEvaluations,
        boolean truncated) {
    public ProxyPolicyBatchEvaluation {
        Objects.requireNonNull(refreshStatus, "refreshStatus");
        Objects.requireNonNull(actionCounts, "actionCounts");
        Objects.requireNonNull(retainedEvaluations, "retainedEvaluations");
        if (totalObservations < 0 || advisoryEnforcementRuleBlocks < 0
                || retainedEvaluations.size() > totalObservations) {
            throw new IllegalArgumentException("invalid proxy policy batch evaluation");
        }
        actionCounts = Map.copyOf(actionCounts);
        retainedEvaluations = List.copyOf(retainedEvaluations);
    }
}
