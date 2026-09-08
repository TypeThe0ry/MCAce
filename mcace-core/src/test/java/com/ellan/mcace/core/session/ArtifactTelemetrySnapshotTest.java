package com.ellan.mcace.core.session;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

final class ArtifactTelemetrySnapshotTest {
    @Test
    void evaluatesExactExpiryAndClockRollbackWithoutOverflow() {
        Instant received = Instant.parse("2026-09-08T00:00:00Z");
        Duration ttl = Duration.ofSeconds(30);
        assertEquals(ArtifactTelemetrySnapshot.Freshness.FRESH,
                new ArtifactTelemetrySnapshot("s", 0, received, received.plusSeconds(29), ttl).freshness());
        assertEquals(ArtifactTelemetrySnapshot.Freshness.STALE,
                new ArtifactTelemetrySnapshot("s", 1, received, received.plus(ttl), ttl).freshness());
        assertEquals(ArtifactTelemetrySnapshot.Freshness.CLOCK_ANOMALY,
                new ArtifactTelemetrySnapshot("s", 1, received, received.minusNanos(1), ttl).freshness());
        assertEquals(ArtifactTelemetrySnapshot.Freshness.STALE,
                new ArtifactTelemetrySnapshot("s", 1, Instant.MIN, Instant.MAX, ttl).freshness());
    }

    @Test
    void rejectsInvalidSnapshotInputs() {
        Instant now = Instant.EPOCH;
        assertThrows(IllegalArgumentException.class,
                () -> new ArtifactTelemetrySnapshot("s", 0, now, now, Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> new ArtifactTelemetrySnapshot("s", -1, now, now, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class,
                () -> new ArtifactTelemetrySnapshot(" ", 0, now, now, Duration.ofSeconds(1)));
    }
}
