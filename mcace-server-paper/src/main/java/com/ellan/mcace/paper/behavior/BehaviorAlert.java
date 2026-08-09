package com.ellan.mcace.paper.behavior;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record BehaviorAlert(
        UUID playerId,
        String provider,
        String providerVersion,
        String check,
        String stableCheck,
        double violationLevel,
        boolean experimental,
        Instant observedAt) {
    public BehaviorAlert {
        Objects.requireNonNull(playerId, "playerId");
        provider = bounded(provider, "provider", 24);
        providerVersion = bounded(providerVersion, "providerVersion", 32);
        check = bounded(check, "check", 64);
        stableCheck = stableCheck == null || stableCheck.isBlank()
                ? check.toLowerCase(java.util.Locale.ROOT) : bounded(stableCheck, "stableCheck", 96);
        if (!Double.isFinite(violationLevel) || violationLevel < 0.0D) {
            throw new IllegalArgumentException("violationLevel must be finite and non-negative");
        }
        Objects.requireNonNull(observedAt, "observedAt");
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
