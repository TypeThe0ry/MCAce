package com.ellan.mcace.core.proxy;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Sanitized server-side signal from a provider such as Grim or Vulcan. */
public record ServerBehaviorObservation(
        UUID playerId,
        String sessionId,
        String provider,
        String signal,
        Instant observedAt) {
    public ServerBehaviorObservation {
        Objects.requireNonNull(playerId, "playerId");
        sessionId = Objects.requireNonNull(sessionId, "sessionId");
        provider = Objects.requireNonNull(provider, "provider");
        signal = Objects.requireNonNull(signal, "signal");
        Objects.requireNonNull(observedAt, "observedAt");
        validate(sessionId, 128, "sessionId");
        validate(provider, 64, "provider");
        validate(signal, 128, "signal");
    }

    private static void validate(String value, int max, String field) {
        if (value.isBlank() || value.length() > max || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(field + " is outside the bounded contract");
        }
    }
}
