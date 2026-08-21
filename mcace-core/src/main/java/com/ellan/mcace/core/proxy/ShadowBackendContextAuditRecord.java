package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.DispositionAction;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/** Content-free shadow result. It intentionally cannot be converted into a disposition event. */
public record ShadowBackendContextAuditRecord(
        UUID playerId,
        String proxyId,
        String backendId,
        String worldId,
        String gameMode,
        Instant observedAt,
        Instant evaluatedAt,
        int observationCount,
        int consistencyIssueCount,
        Map<DispositionAction, Integer> actionCounts,
        ProxyPolicyRefreshStatus policyStatus) {
    public ShadowBackendContextAuditRecord {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(proxyId, "proxyId");
        Objects.requireNonNull(backendId, "backendId");
        Objects.requireNonNull(worldId, "worldId");
        Objects.requireNonNull(gameMode, "gameMode");
        Objects.requireNonNull(observedAt, "observedAt");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        Objects.requireNonNull(actionCounts, "actionCounts");
        Objects.requireNonNull(policyStatus, "policyStatus");
        if (observationCount < 0 || consistencyIssueCount < 0
                || actionCounts.entrySet().stream().anyMatch(entry -> entry.getKey() == null
                || entry.getValue() == null || entry.getValue() < 0)) {
            throw new IllegalArgumentException("invalid shadow backend context audit summary");
        }
        EnumMap<DispositionAction, Integer> copy = new EnumMap<>(DispositionAction.class);
        copy.putAll(actionCounts);
        actionCounts = Map.copyOf(copy);
    }
}
