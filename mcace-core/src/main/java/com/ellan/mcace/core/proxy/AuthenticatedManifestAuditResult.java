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
        return new AuthenticatedManifestDispositionEvent(
                playerId,
                sessionId,
                evaluatedAt,
                evaluation.highestAction(),
                evaluation.winningRuleId(),
                evaluation.refreshStatus(),
                evaluation.activePolicyVersion(),
                evaluation.activePolicySequence(),
                evaluation.activePolicyExpiresAt());
    }
}
