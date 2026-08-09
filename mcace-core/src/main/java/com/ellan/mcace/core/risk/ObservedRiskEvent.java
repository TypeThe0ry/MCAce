package com.ellan.mcace.core.risk;

import java.time.Instant;
import java.util.Objects;

public record ObservedRiskEvent(RiskEventType type, String source, Instant observedAt, boolean corroborated) {
    public ObservedRiskEvent {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(observedAt, "observedAt");
        if (source.isBlank()) {
            throw new IllegalArgumentException("source must not be blank");
        }
    }
}
