package com.ellan.mcace.core.persistence;

import com.ellan.mcace.core.risk.RiskEventType;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record RiskEventAuditRecord(
        UUID eventId,
        String sessionId,
        UUID playerId,
        RiskEventType type,
        int weight,
        String source,
        ObservationOrigin origin,
        boolean corroborated,
        Instant observedAt,
        String detailsJson) {
    public RiskEventAuditRecord {
        Objects.requireNonNull(eventId, "eventId");
        sessionId = Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(type, "type");
        source = Objects.requireNonNull(source, "source");
        Objects.requireNonNull(origin, "origin");
        Objects.requireNonNull(observedAt, "observedAt");
        detailsJson = Objects.requireNonNull(detailsJson, "detailsJson");
        if (weight < 0 || source.isBlank() || detailsJson.isBlank()) {
            throw new IllegalArgumentException("invalid risk event audit record");
        }
    }
}
