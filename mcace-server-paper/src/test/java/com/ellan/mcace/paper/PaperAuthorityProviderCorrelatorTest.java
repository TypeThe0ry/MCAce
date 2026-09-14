package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.authority.BackendAuthorityProfile;
import com.ellan.mcace.paper.behavior.BehaviorAlert;
import com.ellan.mcace.protocol.ProtocolConstants;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

final class PaperAuthorityProviderCorrelatorTest {
    private static final UUID PLAYER =
            UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final Instant NOW = Instant.parse("2026-08-25T08:00:00Z");
    private static final AtomicLong EVENT_SEQUENCE = new AtomicLong();

    @Test
    void requiresExactReviewedProviderContractAndIndependentQuorum() {
        MutableClock clock = new MutableClock(NOW);
        PaperAuthorityProviderCorrelator correlator =
                new PaperAuthorityProviderCorrelator(profile(2, Duration.ZERO), clock);

        assertTrue(correlator.accept(alert(
                "grim", "wrong-version", "movement-stable", false, NOW)).isEmpty());
        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "experimental-family", false, NOW)).isEmpty());
        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", true, NOW)).isEmpty());
        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, NOW.plusMillis(1))).isEmpty());

        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, NOW.minusMillis(1))).isEmpty());
        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, NOW)).isEmpty());
        assertTrue(correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, NOW.minusMillis(1))).isEmpty());
        PaperAuthorityProviderCorrelator.CorrelatedProviders correlated = correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, NOW)).orElseThrow();

        assertEquals(List.of("grim", "vulcan"), correlated.providers().stream()
                .map(input -> input.providerId()).toList());
        assertEquals(NOW, correlated.observedAt());
    }

    @Test
    void committedEvidenceIsSingleUseAndFreshEventsMustReachThresholdAgain() {
        MutableClock clock = new MutableClock(NOW);
        PaperAuthorityProviderCorrelator correlator =
                new PaperAuthorityProviderCorrelator(profile(2, Duration.ofSeconds(2)), clock);
        reachQuorum(correlator, NOW);
        correlator.committed(PLAYER, NOW, NOW, NOW);

        clock.set(NOW.plusSeconds(3));
        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, clock.instant())).isEmpty());
        assertTrue(correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, clock.instant())).isEmpty());
        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, clock.instant())).isEmpty());
        assertTrue(correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, clock.instant())).isPresent());
    }

    @Test
    void canonicalSelectionEmitsAtMostOneProviderPerTrustDomain() {
        MutableClock clock = new MutableClock(NOW);
        BackendAuthorityProfile profile = new BackendAuthorityProfile(
                List.of(
                        provider("grim-domain", "grim", 1),
                        provider("grim-domain", "grim-alternative", 1),
                        provider("vulcan-domain", "vulcan", 1)),
                2, Duration.ofSeconds(10), Duration.ZERO);
        PaperAuthorityProviderCorrelator correlator =
                new PaperAuthorityProviderCorrelator(profile, clock);

        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, NOW)).isEmpty());
        assertTrue(correlator.accept(alert(
                "grim-alternative", "1.0.0", "movement-stable", false, NOW)).isEmpty());
        PaperAuthorityProviderCorrelator.CorrelatedProviders correlated = correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, NOW)).orElseThrow();

        assertEquals(2, correlated.providers().size());
        assertEquals(2, correlated.providers().stream()
                .map(input -> input.trustDomainId()).distinct().count());
    }

    @Test
    void cooldownStartsAtDurableCommitRatherThanDelayedProviderTimestamp() {
        MutableClock clock = new MutableClock(NOW);
        PaperAuthorityProviderCorrelator correlator =
                new PaperAuthorityProviderCorrelator(profile(1, Duration.ofSeconds(10)), clock);
        PaperAuthorityProviderCorrelator.CorrelatedProviders delayed = reachQuorum(
                correlator, NOW.minusSeconds(5));
        clock.set(NOW);
        correlator.committed(
                PLAYER, delayed.observedAt(), delayed.observedAt(), clock.instant());

        clock.set(NOW.plusSeconds(6));
        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, clock.instant())).isEmpty());
        assertTrue(correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, clock.instant())).isEmpty(),
                "a delayed observation must not shorten the post-commit cooldown");

        clock.set(NOW.plusSeconds(11));
        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, clock.instant())).isPresent(),
                "fresh evidence accumulated during cooldown may publish only after commit plus cooldown");
    }

    @Test
    void refreshedGrantDropsEventsThatPredateItsIssuanceBoundary() {
        MutableClock clock = new MutableClock(NOW);
        PaperAuthorityProviderCorrelator correlator =
                new PaperAuthorityProviderCorrelator(profile(2, Duration.ZERO), clock);
        correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, NOW.minusSeconds(1)));
        correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, NOW.minusSeconds(1)));

        correlator.grantAdvanced(PLAYER, NOW);
        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, NOW)).isEmpty());
        assertTrue(correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, NOW)).isEmpty());
    }

    @Test
    void nanosecondPaperEventTimesAreCanonicalizedToWireMilliseconds() {
        MutableClock clock = new MutableClock(NOW.plusMillis(1));
        PaperAuthorityProviderCorrelator correlator =
                new PaperAuthorityProviderCorrelator(profile(1, Duration.ZERO), clock);
        Instant eventTime = NOW.plusNanos(456_789L);

        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, eventTime)).isEmpty());
        PaperAuthorityProviderCorrelator.CorrelatedProviders correlated = correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, eventTime)).orElseThrow();

        assertEquals(NOW, correlated.observedAt());
        correlated.providers().forEach(input -> {
            assertEquals(NOW, input.windowStartedAt());
            assertEquals(NOW, input.windowEndedAt());
        });
    }

    @Test
    void outOfOrderProviderEventsUseTemporalMinAndMaxRatherThanArrivalOrder() {
        MutableClock clock = new MutableClock(NOW.plusSeconds(2));
        PaperAuthorityProviderCorrelator correlator =
                new PaperAuthorityProviderCorrelator(profile(2, Duration.ZERO), clock);
        Instant first = NOW.plusSeconds(1);
        Instant second = NOW.plusSeconds(2);

        // Async adapters can report T2 before T1. This must not construct a backwards window.
        correlator.accept(alert("grim", "1.0.0", "movement-stable", false, second));
        correlator.accept(alert("grim", "1.0.0", "movement-stable", false, first));
        correlator.accept(alert("vulcan", "1.0.0", "movement-stable", false, second));
        PaperAuthorityProviderCorrelator.CorrelatedProviders correlated = correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, first)).orElseThrow();

        assertEquals(second, correlated.observedAt());
        correlated.providers().forEach(provider -> {
            assertEquals(first, provider.windowStartedAt());
            assertEquals(second, provider.windowEndedAt());
        });
    }

    @Test
    void recoveredDurableTimesPreserveExactCooldownAndSingleUseBoundary() {
        MutableClock clock = new MutableClock(NOW.plusSeconds(5));
        PaperAuthorityProviderCorrelator correlator =
                new PaperAuthorityProviderCorrelator(profile(1, Duration.ofSeconds(10)), clock);
        correlator.recovered(
                PLAYER, java.util.Optional.of(NOW.minusSeconds(1)),
                java.util.Optional.of(NOW));

        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, NOW.minusSeconds(1))).isEmpty(),
                "recovered consumed evidence cannot be reused");
        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, NOW.plusSeconds(5))).isEmpty());
        assertTrue(correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, NOW.plusSeconds(5))).isEmpty(),
                "restart must retain the exact durable issuance cooldown");

        clock.set(NOW.plusSeconds(10));
        PaperAuthorityProviderCorrelator.CorrelatedProviders correlated = correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false,
                NOW.plusSeconds(9))).orElseThrow();
        assertEquals(NOW.plusSeconds(9), correlated.observedAt(),
                "provider time becomes eligible exactly at last observedAt plus cooldown");
    }

    @Test
    void providerObservationCooldownIsIndependentFromDurableIssuanceCooldown() {
        MutableClock clock = new MutableClock(NOW.plusSeconds(15));
        PaperAuthorityProviderCorrelator correlator =
                new PaperAuthorityProviderCorrelator(profile(1, Duration.ofSeconds(10)), clock);
        correlator.recovered(
                PLAYER, java.util.Optional.of(NOW), java.util.Optional.of(NOW));

        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, NOW.plusSeconds(5))).isEmpty());
        assertTrue(correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, NOW.plusSeconds(5))).isEmpty(),
                "wall-clock issuance cooldown alone cannot publish stale provider time");
        PaperAuthorityProviderCorrelator.CorrelatedProviders exact = correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false,
                NOW.plusSeconds(10))).orElseThrow();
        assertEquals(NOW.plusSeconds(10), exact.observedAt());
    }

    @Test
    void sharedMaximumThresholdIsReachableWithoutDequeEviction() {
        MutableClock clock = new MutableClock(NOW);
        int maximum = ProtocolConstants.MAX_BACKEND_AUTHORITY_OBSERVATIONS_PER_PROVIDER;
        PaperAuthorityProviderCorrelator correlator =
                new PaperAuthorityProviderCorrelator(profile(maximum, Duration.ZERO), clock);

        for (int index = 0; index < maximum; index++) {
            assertTrue(correlator.accept(alert(
                    "grim", "1.0.0", "movement-stable", false, NOW)).isEmpty());
        }
        for (int index = 0; index < maximum - 1; index++) {
            assertTrue(correlator.accept(alert(
                    "vulcan", "1.0.0", "movement-stable", false, NOW)).isEmpty());
        }
        PaperAuthorityProviderCorrelator.CorrelatedProviders correlated = correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, NOW)).orElseThrow();
        assertTrue(correlated.providers().stream()
                .allMatch(provider -> provider.observedCount() == maximum));
    }

    @Test
    void repeatedProviderEventIdentityCannotSatisfyAuthorityThreshold() {
        MutableClock clock = new MutableClock(NOW);
        PaperAuthorityProviderCorrelator correlator =
                new PaperAuthorityProviderCorrelator(profile(2, Duration.ZERO), clock);
        BehaviorAlert grimFirst = alert(
                "grim", "1.0.0", "movement-stable", false, NOW);
        BehaviorAlert vulcanFirst = alert(
                "vulcan", "1.0.0", "movement-stable", false, NOW);

        assertTrue(correlator.accept(grimFirst).isEmpty());
        assertTrue(correlator.accept(grimFirst).isEmpty(),
                "one replayed Grim callback must still count once");
        assertTrue(correlator.accept(vulcanFirst).isEmpty());
        assertTrue(correlator.accept(vulcanFirst).isEmpty(),
                "one replayed Vulcan callback must still count once");
        assertTrue(correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, NOW)).isEmpty());
        assertTrue(correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, NOW)).isPresent(),
                "two distinct native events per provider satisfy the frozen threshold");
    }

    private static PaperAuthorityProviderCorrelator.CorrelatedProviders reachQuorum(
            PaperAuthorityProviderCorrelator correlator, Instant observedAt) {
        correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, observedAt));
        correlator.accept(alert(
                "grim", "1.0.0", "movement-stable", false, observedAt));
        correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, observedAt));
        return correlator.accept(alert(
                "vulcan", "1.0.0", "movement-stable", false, observedAt)).orElseThrow();
    }

    private static BackendAuthorityProfile profile(int threshold, Duration cooldown) {
        return new BackendAuthorityProfile(
                List.of(
                        provider("grim-domain", "grim", threshold),
                        provider("vulcan-domain", "vulcan", threshold)),
                2, Duration.ofSeconds(10), cooldown);
    }

    private static BackendAuthorityProfile.ProviderContract provider(
            String domain, String providerId, int threshold) {
        return new BackendAuthorityProfile.ProviderContract(
                domain, providerId, "1.0.0", "movement-stable", threshold);
    }

    private static BehaviorAlert alert(
            String provider,
            String version,
            String stableFamily,
            boolean experimental,
            Instant observedAt) {
        return new BehaviorAlert(
                PLAYER, BehaviorAlert.providerEventIdSha256(
                        provider, PLAYER.toString(), stableFamily,
                        Long.toString(EVENT_SEQUENCE.incrementAndGet())),
                provider, version, "raw-check", stableFamily,
                4.0D, experimental, observedAt);
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        private MutableClock(Instant now) {
            this.now = now;
        }

        void set(Instant value) {
            now = value;
        }

        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
