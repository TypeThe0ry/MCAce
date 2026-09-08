package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.*;
import com.ellan.mcace.core.session.ArtifactTelemetrySnapshot;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class ArtifactTelemetryQueryTest {
    private final String player = UUID.randomUUID().toString();

    @Test void validatesBeforeLookingUpState() {
        AtomicInteger calls = new AtomicInteger();
        var query = new ArtifactTelemetryQuery((id, age) -> { calls.incrementAndGet(); return Optional.empty(); });
        for (String[] args : new String[][] { {}, {"bad"}, {"1-1-1-1-1"}, {player, "0"},
                {player, "3601"}, {player, "-1"}, {player, "999999999999"}, {player, "1", "extra"} }) {
            assertEquals(ArtifactTelemetryQuery.USAGE, query.execute(args));
        }
        assertEquals(0, calls.get());
        assertTrue(query.execute(new String[] {player}).contains("state=UNAVAILABLE"));
        assertEquals(1, calls.get());
    }

    @Test void rendersFreshnessWithoutSessionOrArtifactIdentities() {
        Instant now = Instant.parse("2026-09-08T00:00:00Z");
        var query = new ArtifactTelemetryQuery((id, age) -> {
            assertEquals(UUID.fromString(player), id);
            return Optional.of(new ArtifactTelemetrySnapshot("private-session", 3, now,
                    now.plusSeconds(ArtifactTelemetryQuery.DEFAULT_WINDOW_SECONDS), age));
        });
        String stale = query.execute(new String[] {player});
        assertTrue(stale.contains("diagnosticWindowSeconds=" + ArtifactTelemetryQuery.DEFAULT_WINDOW_SECONDS + " state=STALE"));
        assertTrue(stale.contains("updateSequence=3"));
        assertFalse(stale.contains("private-session"));
        assertFalse(stale.contains(player));
        assertTrue(query.execute(new String[] {player,
                String.valueOf(ArtifactTelemetryQuery.DEFAULT_WINDOW_SECONDS + 1)}).contains("state=FRESH"));
        assertTrue(stale.contains("not cheat-free proof or an execution receipt"));
    }

    @Test void defaultWindowCoversNormalObservationCadence() {
        long interval = com.ellan.mcace.protocol.ProtocolConstants.ARTIFACT_OBSERVATION_INTERVAL.toSeconds();
        assertEquals(interval * 3, ArtifactTelemetryQuery.DEFAULT_WINDOW_SECONDS);
        assertTrue(ArtifactTelemetryQuery.DEFAULT_WINDOW_SECONDS <= 3600);
        Instant now = Instant.parse("2026-09-08T00:00:00Z");
        var query = new ArtifactTelemetryQuery((id, age) -> Optional.of(
                new ArtifactTelemetrySnapshot("s", 0, now, now.plusSeconds(interval), age)));
        assertTrue(query.execute(new String[] {player}).contains("state=FRESH"));
    }
}
