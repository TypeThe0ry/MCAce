package com.ellan.mcace.cloudclient;

import com.ellan.mcace.core.persistence.ObservationOrigin;
import com.ellan.mcace.core.risk.RiskEventType;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public record CloudRiskEvent(
        UUID eventId,
        String sessionId,
        UUID playerId,
        RiskEventType type,
        String sourceComponent,
        ObservationOrigin origin,
        boolean corroborated,
        Instant observedAt,
        Map<String, Object> details) {
    public CloudRiskEvent {
        Objects.requireNonNull(eventId, "eventId");
        sessionId = sessionId == null ? "" : sessionId.strip();
        if (sessionId.length() > 256) {
            throw new IllegalArgumentException("sessionId exceeds 256 characters");
        }
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(type, "type");
        sourceComponent = bounded(sourceComponent, "sourceComponent", 64);
        Objects.requireNonNull(origin, "origin");
        Objects.requireNonNull(observedAt, "observedAt");
        details = Map.copyOf(Objects.requireNonNull(details, "details"));
    }

    private static String bounded(String value, String field, int maximum) {
        Objects.requireNonNull(value, field);
        String normalized = value.strip();
        if (normalized.isEmpty() || normalized.length() > maximum) {
            throw new IllegalArgumentException(field + " must contain 1-" + maximum + " characters");
        }
        return normalized;
    }
}
