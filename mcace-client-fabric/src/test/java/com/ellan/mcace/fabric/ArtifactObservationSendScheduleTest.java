package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;

final class ArtifactObservationSendScheduleTest {
    @Test
    void firstChangeIsImmediateAndLaterChangesCoalesceBehindFullCooldown() {
        MutableClock clock = new MutableClock(Instant.EPOCH);
        ArtifactObservationSendSchedule schedule =
                new ArtifactObservationSendSchedule(clock, Duration.ofMinutes(5));
        schedule.activate(9L);

        assertFalse(schedule.takeDue(9L));
        assertTrue(schedule.takeDue(9L, true), "the first changed snapshot is immediate");
        assertFalse(schedule.takeDue(9L, true), "the scheduler remains single-flight while awaiting ACK");
        schedule.markSent(9L);
        schedule.complete(9L);

        assertFalse(schedule.takeDue(9L, true), "a later change must not punch through cooldown");
        clock.advance(Duration.ofMinutes(4).plusSeconds(59));
        assertFalse(schedule.takeDue(9L, true));
        clock.advance(Duration.ofSeconds(1));
        assertTrue(schedule.takeDue(9L, true));
    }

    @Test
    void transientFailuresKeepAttemptActiveDirtyAndUseBoundedBackoff() {
        MutableClock clock = new MutableClock(Instant.EPOCH);
        ArtifactObservationSendSchedule schedule =
                new ArtifactObservationSendSchedule(clock, Duration.ofMinutes(5));
        schedule.activate(3L);

        assertTrue(schedule.takeDue(3L, true));
        schedule.fail(3L);
        assertTrue(schedule.isActive(3L));
        assertFalse(schedule.isInFlight(3L));
        assertFalse(schedule.takeDue(3L, true), "persistent dirty state cannot erase retry backoff");
        clock.advance(Duration.ofMillis(999));
        assertFalse(schedule.takeDue(3L, true));
        clock.advance(Duration.ofMillis(1));
        assertTrue(schedule.takeDue(3L, true));

        schedule.fail(3L);
        clock.advance(Duration.ofMillis(1_999));
        assertFalse(schedule.takeDue(3L, true));
        clock.advance(Duration.ofMillis(1));
        assertTrue(schedule.takeDue(3L, true), "the second retry backs off to two seconds");
    }

    @Test
    void ackTimeoutStartsOnlyAfterTransportSendAndLateAckCanComplete() {
        MutableClock clock = new MutableClock(Instant.EPOCH);
        ArtifactObservationSendSchedule schedule =
                new ArtifactObservationSendSchedule(clock, Duration.ofMinutes(5));
        schedule.activate(7L);
        assertTrue(schedule.takeDue(7L, true));

        clock.advance(Duration.ofMinutes(1));
        assertFalse(schedule.timeoutIfDue(7L, Duration.ofSeconds(30)),
                "scan time is not an ACK timeout");
        schedule.markSent(7L);
        clock.advance(Duration.ofSeconds(29));
        assertFalse(schedule.timeoutIfDue(7L, Duration.ofSeconds(30)));
        clock.advance(Duration.ofSeconds(1));
        assertTrue(schedule.timeoutIfDue(7L, Duration.ofSeconds(30)));
        assertFalse(schedule.isInFlight(7L));

        schedule.complete(7L); // an authentic result may arrive after the local timeout
        assertFalse(schedule.takeDue(7L, true));
        clock.advance(Duration.ofMinutes(5));
        assertTrue(schedule.takeDue(7L, true));
    }

    @Test
    void signedRateLimitHintIsHonoredButCannotStallBeyondOneInterval() {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-14T00:00:00Z"));
        ArtifactObservationSendSchedule schedule =
                new ArtifactObservationSendSchedule(clock, Duration.ofMinutes(5));
        schedule.activate(4L);
        assertTrue(schedule.takeDue(4L, true));

        schedule.retryAt(4L, clock.millis() + Duration.ofMinutes(2).toMillis());
        clock.advance(Duration.ofMinutes(2).minusMillis(1));
        assertFalse(schedule.takeDue(4L, true));
        clock.advance(Duration.ofMillis(1));
        assertTrue(schedule.takeDue(4L, true));

        schedule.retryAt(4L, Long.MAX_VALUE);
        clock.advance(Duration.ofMinutes(5).minusMillis(1));
        assertFalse(schedule.takeDue(4L, true));
        clock.advance(Duration.ofMillis(1));
        assertTrue(schedule.takeDue(4L, true), "a server hint is capped to the normal interval");
    }

    @Test
    void cancellationAndReplacementAreTheOnlyTerminalScheduleTransitions() {
        MutableClock clock = new MutableClock(Instant.EPOCH);
        ArtifactObservationSendSchedule schedule =
                new ArtifactObservationSendSchedule(clock, Duration.ofSeconds(1));
        schedule.activate(1L);
        schedule.cancel();
        clock.advance(Duration.ofSeconds(2));
        assertFalse(schedule.takeDue(1L, true));

        schedule.activate(2L);
        assertFalse(schedule.isActive(1L));
        assertTrue(schedule.isActive(2L));
        assertFalse(schedule.takeDue(1L, true));
        assertTrue(schedule.takeDue(2L, true));
    }

    @Test
    void rejectsNonPositiveConfigurationAttemptAndTimeout() {
        MutableClock clock = new MutableClock(Instant.EPOCH);
        assertThrows(IllegalArgumentException.class,
                () -> new ArtifactObservationSendSchedule(clock, Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> new ArtifactObservationSendSchedule(clock, Duration.ofNanos(1L)));
        ArtifactObservationSendSchedule schedule =
                new ArtifactObservationSendSchedule(clock, Duration.ofSeconds(1));
        assertThrows(IllegalArgumentException.class, () -> schedule.activate(0L));
        schedule.activate(1L);
        assertThrows(IllegalArgumentException.class,
                () -> schedule.timeoutIfDue(1L, Duration.ZERO));
    }

    @Test
    void pureResourcePackReorderIsAChangedRuntimeSnapshot() {
        List<String> previous = List.of("file/base.zip", "file/high-priority.zip", "vanilla");
        List<String> reordered = List.of("file/high-priority.zip", "file/base.zip", "vanilla");
        ArtifactObservationSendSchedule schedule = new ArtifactObservationSendSchedule(
                new MutableClock(Instant.EPOCH), Duration.ofMinutes(5));
        schedule.activate(19L);

        assertFalse(schedule.takeDue(19L, false));
        boolean orderChanged = MCAceFabricClient.selectedPackOrderChanged(reordered, previous);
        assertTrue(orderChanged);
        assertTrue(schedule.takeDue(19L, orderChanged),
                "a pure encounter-order change must immediately schedule a fresh snapshot");
        assertFalse(MCAceFabricClient.selectedPackOrderChanged(previous, List.copyOf(previous)));
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advance(Duration amount) {
            instant = instant.plus(amount);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
