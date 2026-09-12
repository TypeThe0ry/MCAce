package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.ArtifactType;
import com.ellan.mcace.core.disposition.Confidence;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class ServerBehaviorCorrelatorTest {
    private static final UUID PLAYER = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final Instant NOW = Instant.parse("2026-08-22T00:00:00Z");

    @Test
    void upgradesClientArtifactOnlyAfterIndependentProviderSignal() {
        ArtifactObservation client = observation();
        ServerBehaviorObservation behavior = new ServerBehaviorObservation(
                PLAYER, "session-123456789012", "grim", "Simulation", NOW.minusSeconds(3));

        ArtifactObservation correlated = new ServerBehaviorCorrelator().correlate(
                PLAYER, "session-123456789012", NOW.minusSeconds(5), client, behavior,
                Duration.ofSeconds(30), NOW).orElseThrow();

        assertEquals(ObservationOrigin.SERVER_CONFIRMED, correlated.origin());
        assertEquals(Confidence.CONFIRMED, correlated.confidence());
        assertEquals("grim", correlated.metadata().get("correlated_provider"));
    }

    @Test
    void rejectsClientOnlyOrExpiredSignals() {
        ArtifactObservation client = observation();
        ServerBehaviorObservation behavior = new ServerBehaviorObservation(
                PLAYER, "session-123456789012", "vulcan", "Speed", NOW.minusSeconds(2));
        assertTrue(new ServerBehaviorCorrelator().correlate(
                PLAYER, "session-123456789012", NOW.minusSeconds(2),
                new ArtifactObservation(client.type(), client.identifier(), client.version(), client.sha256(),
                        client.metadata(), ObservationOrigin.INFERRED, client.confidence(), false),
                behavior, Duration.ofSeconds(30), NOW).isEmpty());
        assertTrue(new ServerBehaviorCorrelator().correlate(
                PLAYER, "session-123456789012", NOW.minusSeconds(90), client, behavior,
                Duration.ofSeconds(30), NOW).isEmpty());
    }

    private static ArtifactObservation observation() {
        return new ArtifactObservation(
                ArtifactType.MOD, "meteor-client", "1.21.11", "ab".repeat(32),
                Map.of(),
                ObservationOrigin.CLIENT_REPORTED, Confidence.LOW, false);
    }
}
