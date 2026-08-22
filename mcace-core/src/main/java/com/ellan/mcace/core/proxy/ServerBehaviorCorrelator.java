package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.Confidence;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Converts a client artifact observation into trusted evidence only when an independent server
 * provider observes the same session inside a bounded correlation window.
 */
public final class ServerBehaviorCorrelator {
    public Optional<ArtifactObservation> correlate(
            UUID playerId,
            String sessionId,
            Instant clientObservedAt,
            ArtifactObservation clientObservation,
            ServerBehaviorObservation serverObservation,
            Duration window,
            Instant evaluatedAt) {
        Objects.requireNonNull(playerId, "playerId");
        if (sessionId == null || sessionId.isBlank()) throw new IllegalArgumentException("sessionId is required");
        Objects.requireNonNull(clientObservedAt, "clientObservedAt");
        Objects.requireNonNull(clientObservation, "clientObservation");
        Objects.requireNonNull(serverObservation, "serverObservation");
        Objects.requireNonNull(window, "window");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        if (window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("correlation window must be positive");
        }
        if (!playerId.equals(serverObservation.playerId())
                || !sessionId.equals(serverObservation.sessionId())
                || clientObservation.origin() != ObservationOrigin.CLIENT_REPORTED
                || !serverObservation.observedAt().isBefore(evaluatedAt.plusNanos(1))) {
            return Optional.empty();
        }
        long delta = Math.abs(Duration.between(clientObservedAt, serverObservation.observedAt()).toMillis());
        if (!serverObservation.observedAt().isAfter(evaluatedAt.minus(window))
                || delta > window.toMillis()) {
            return Optional.empty();
        }
        Map<String, String> metadata = new LinkedHashMap<>(clientObservation.metadata());
        metadata.put("correlated_provider", serverObservation.provider());
        metadata.put("correlated_signal", serverObservation.signal());
        metadata.put("correlation_window_ms", Long.toString(window.toMillis()));
        metadata.put("client_origin", ObservationOrigin.CLIENT_REPORTED.name());
        return Optional.of(new ArtifactObservation(
                clientObservation.type(), clientObservation.identifier(), clientObservation.version(),
                clientObservation.sha256(), metadata, ObservationOrigin.SERVER_CONFIRMED,
                Confidence.CONFIRMED, clientObservation.foundationSecurity()));
    }

}
