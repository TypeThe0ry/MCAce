package com.ellan.mcace.core.proxy;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Explainable, observation-only outcome suitable for an audit sink or operator timeline. */
public record ObservationAuditResult(
        UUID playerId,
        String sessionId,
        String transferId,
        Instant completedAt,
        long totalBytes,
        List<ProxyPolicyEvaluation> evaluations) {
    public ObservationAuditResult {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(transferId, "transferId");
        Objects.requireNonNull(completedAt, "completedAt");
        Objects.requireNonNull(evaluations, "evaluations");
        if (sessionId.isBlank() || transferId.isBlank() || totalBytes < 0) {
            throw new IllegalArgumentException("invalid observation audit result");
        }
        evaluations = List.copyOf(evaluations);
    }
}
