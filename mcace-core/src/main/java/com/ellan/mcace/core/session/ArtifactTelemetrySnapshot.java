package com.ellan.mcace.core.session;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/** Server-receipt freshness of client claims; never a cheat verdict or an action receipt. */
public record ArtifactTelemetrySnapshot(
        String sessionId, long updateSequence, Instant receivedAt, Instant evaluatedAt,
        Duration maximumAge) {
    public ArtifactTelemetrySnapshot {
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(receivedAt, "receivedAt");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        Objects.requireNonNull(maximumAge, "maximumAge");
        if (sessionId.isBlank() || updateSequence < 0 || maximumAge.isZero() || maximumAge.isNegative()) {
            throw new IllegalArgumentException("session, sequence and maximum age must be valid");
        }
    }

    public enum Freshness { FRESH, STALE, CLOCK_ANOMALY }

    /** Point-in-time check for a queued report, not an authorization or an atomic action lease. */
    public boolean matchesFreshReceipt(String session, long sequence, Instant receipt) {
        return sessionId.equals(session) && updateSequence == sequence && receivedAt.equals(receipt)
                && freshness() == Freshness.FRESH;
    }

    public Freshness freshness() {
        if (evaluatedAt.isBefore(receivedAt)) return Freshness.CLOCK_ANOMALY;
        return Duration.between(receivedAt, evaluatedAt).compareTo(maximumAge) < 0
                ? Freshness.FRESH : Freshness.STALE;
    }
}
