package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.DispositionAction;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Durable operational summary for a validated dynamic observation update.
 * It intentionally contains no paths, filenames, hashes, raw manifests, rule IDs, or content.
 */
public record ArtifactObservationAuditRecord(
        UUID playerId, Instant observedAt, Instant evaluatedAt,
        int observationCount, int consistencyIssueCount, Map<DispositionAction, Integer> actionCounts,
        ProxyPolicyRefreshStatus policyStatus) {
    public ArtifactObservationAuditRecord {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(observedAt, "observedAt");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        Objects.requireNonNull(actionCounts, "actionCounts");
        Objects.requireNonNull(policyStatus, "policyStatus");
        if (observationCount < 0 || consistencyIssueCount < 0
                || actionCounts.size() > DispositionAction.values().length
                || actionCounts.entrySet().stream().anyMatch(entry -> entry.getKey() == null || entry.getValue() == null
                        || entry.getValue() < 0)) {
            throw new IllegalArgumentException("invalid artifact observation audit summary");
        }
        EnumMap<DispositionAction, Integer> copy = new EnumMap<>(DispositionAction.class);
        copy.putAll(actionCounts);
        actionCounts = Map.copyOf(copy);
    }
}
