package com.ellan.mcace.paper.behavior;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.cloudclient.CloudRiskEvent;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class BehaviorAlertCorrelatorTest {
    private static final UUID PLAYER = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final Instant NOW = Instant.parse("2026-08-08T12:00:00Z");

    @Test
    void aggregatesFlagsAndAppliesCooldownWithoutClaimingCorroboration() {
        BehaviorAlertCorrelator correlator = new BehaviorAlertCorrelator(
                3, Duration.ofSeconds(10), Duration.ofSeconds(30), 100);

        assertTrue(correlator.accept(alert("grim", "timer", NOW)).isEmpty());
        assertTrue(correlator.accept(alert("grim", "timer", NOW.plusSeconds(1))).isEmpty());
        CloudRiskEvent emitted = correlator.accept(alert("grim", "timer", NOW.plusSeconds(2))).orElseThrow();

        assertFalse(emitted.corroborated());
        assertEquals("grim-adapter", emitted.sourceComponent());
        assertEquals(3, emitted.details().get("flag_count"));
        assertTrue(correlator.accept(alert("grim", "timer", NOW.plusSeconds(3))).isEmpty());
    }

    @Test
    void onlyMarksIndependentProvidersAsCorroborated() {
        BehaviorAlertCorrelator correlator = new BehaviorAlertCorrelator(
                2, Duration.ofSeconds(10), Duration.ZERO, 100);
        assertTrue(correlator.accept(alert("grim", "reach", NOW)).isEmpty());
        assertFalse(correlator.accept(alert("grim", "reach", NOW.plusMillis(1)))
                .orElseThrow().corroborated());
        assertTrue(correlator.accept(alert("vulcan", "reach", NOW.plusMillis(2))).isEmpty());

        CloudRiskEvent emitted = correlator.accept(alert("vulcan", "reach", NOW.plusMillis(3))).orElseThrow();
        assertTrue(emitted.corroborated());
        assertEquals(java.util.List.of("grim", "vulcan"), emitted.details().get("independent_providers"));
    }

    @Test
    void doesNotCorroborateAnUnthresholdedSecondProvider() {
        BehaviorAlertCorrelator correlator = new BehaviorAlertCorrelator(
                2, Duration.ofSeconds(10), Duration.ZERO, 100);
        assertTrue(correlator.accept(alert("grim", "reach", NOW)).isEmpty());
        assertTrue(correlator.accept(alert("vulcan", "reach", NOW.plusMillis(1))).isEmpty());
        CloudRiskEvent emitted = correlator.accept(alert("vulcan", "reach", NOW.plusMillis(2))).orElseThrow();
        assertFalse(emitted.corroborated());
    }

    @Test
    void boundsTrackedKeysAndRemovesPlayerState() {
        BehaviorAlertCorrelator correlator = new BehaviorAlertCorrelator(
                2, Duration.ofSeconds(10), Duration.ZERO, 2);
        correlator.accept(alert("grim", "a", NOW));
        correlator.accept(alert("grim", "b", NOW));
        correlator.accept(alert("grim", "c", NOW));
        assertEquals(2, correlator.trackedKeys());
        correlator.remove(PLAYER);
        assertEquals(0, correlator.trackedKeys());
    }

    private static BehaviorAlert alert(String provider, String check, Instant observedAt) {
        return new BehaviorAlert(PLAYER, provider, "test", check, check, 4.0D, false, observedAt);
    }
}
