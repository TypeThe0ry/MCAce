package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.context.BackendContextReport;
import com.ellan.mcace.core.context.BackendContextCodec;
import com.ellan.mcace.core.disposition.EvaluationContext;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** Source-bound backend context accepted for shadow comparison only. */
public record ShadowBackendContextSnapshot(
        UUID playerId,
        String sessionId,
        String proxyId,
        String backendId,
        String worldId,
        String gameMode,
        long admissionTransportSequence,
        long reportSequence,
        Instant observedAt,
        Instant expiresAt) {
    public ShadowBackendContextSnapshot {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(proxyId, "proxyId");
        Objects.requireNonNull(backendId, "backendId");
        Objects.requireNonNull(worldId, "worldId");
        Objects.requireNonNull(gameMode, "gameMode");
        Objects.requireNonNull(observedAt, "observedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
    }

    static ShadowBackendContextSnapshot from(
            String sessionId, String proxyId, String backendId, BackendContextReport report) {
        return new ShadowBackendContextSnapshot(
                report.playerId(), sessionId, proxyId, backendId, report.worldId(), report.gameMode(),
                report.admissionTransportSequence(), report.reportSequence(), report.observedAt(),
                report.observedAt().plus(BackendContextCodec.MAX_REPORT_AGE));
    }

    EvaluationContext evaluationContext(Instant evaluatedAt) {
        return new EvaluationContext(
                playerId, proxyId, backendId, worldId, gameMode, Set.of(), evaluatedAt);
    }
}
