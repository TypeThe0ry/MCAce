package com.ellan.mcace.core.proxy;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Explainable initial-manifest evaluation, deliberately separate from admission/routing state. */
public record AuthenticatedManifestAuditResult(
        UUID playerId,
        String sessionId,
        Instant evaluatedAt,
        ProxyPolicyBatchEvaluation evaluation,
        List<String> consistencyIssues) {
    public AuthenticatedManifestAuditResult {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        Objects.requireNonNull(evaluation, "evaluation");
        Objects.requireNonNull(consistencyIssues, "consistencyIssues");
        if (sessionId.isBlank()) throw new IllegalArgumentException("sessionId must not be blank");
        consistencyIssues = List.copyOf(consistencyIssues);
    }

    /**
     * Derives a bounded execution event from the aggregate result.  No raw manifest data crosses
     * this boundary.  The batch action counts cover every observation even when retained
     * explanations are truncated, so the highest action cannot be hidden by the audit budget.
     */
    public AuthenticatedManifestDispositionEvent dispositionEvent() {
        com.ellan.mcace.core.disposition.DispositionAction highest = evaluation.actionCounts().keySet().stream()
                .max(java.util.Comparator.comparingInt(com.ellan.mcace.core.disposition.DispositionAction::severity))
                .orElse(com.ellan.mcace.core.disposition.DispositionAction.OBSERVE);
        java.util.Optional<String> rule = evaluation.retainedEvaluations().stream()
                .filter(item -> item.decision().action() == highest)
                .map(item -> item.decision().winningRuleId())
                .flatMap(java.util.Optional::stream)
                .findFirst();
        java.util.Optional<ProxyPolicyEvaluation> first = evaluation.retainedEvaluations().stream().findFirst();
        return new AuthenticatedManifestDispositionEvent(
                playerId,
                sessionId,
                evaluatedAt,
                highest,
                rule,
                evaluation.refreshStatus(),
                first.flatMap(ProxyPolicyEvaluation::activePolicyVersion),
                first.flatMap(ProxyPolicyEvaluation::activePolicySequence),
                first.flatMap(ProxyPolicyEvaluation::activePolicyExpiresAt));
    }
}
