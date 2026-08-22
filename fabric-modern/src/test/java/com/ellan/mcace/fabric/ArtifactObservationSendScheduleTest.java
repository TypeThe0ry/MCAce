package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

final class ArtifactObservationSendScheduleTest {
    @Test
    void refreshIsAttemptBoundSingleFlightAndNeverBurstsToCatchUp() {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-14T00:00:00Z"));
        ArtifactObservationSendSchedule schedule =
                new ArtifactObservationSendSchedule(clock, Duration.ofMinutes(5));

        schedule.activate(7L);
        assertFalse(schedule.takeDue(7L));
        clock.advance(Duration.ofMinutes(5));
        assertTrue(schedule.takeDue(7L));
        assertFalse(schedule.takeDue(7L), "an in-flight refresh must not be duplicated");
        clock.advance(Duration.ofHours(1));
        schedule.complete(7L);
        assertFalse(schedule.takeDue(7L), "completion starts one fresh interval without catch-up bursts");
        clock.advance(Duration.ofMinutes(5));
        assertTrue(schedule.takeDue(7L));
    }

    @Test
    void cancellationAndReplacementInvalidatePreviousAttempts() {
        MutableClock clock = new MutableClock(Instant.EPOCH);
        ArtifactObservationSendSchedule schedule =
                new ArtifactObservationSendSchedule(clock, Duration.ofSeconds(1));

        schedule.activate(1L);
        schedule.cancel();
        clock.advance(Duration.ofSeconds(2));
        assertFalse(schedule.takeDue(1L));
        schedule.activate(2L);
        assertFalse(schedule.isActive(1L));
        assertTrue(schedule.isActive(2L));
        clock.advance(Duration.ofSeconds(1));
        assertFalse(schedule.takeDue(1L));
        assertTrue(schedule.takeDue(2L));
    }

    @Test
    void resourcePackChangesCanTriggerAnImmediateRefreshWithoutBreakingSingleFlight() {
        MutableClock clock = new MutableClock(Instant.EPOCH);
        ArtifactObservationSendSchedule schedule =
                new ArtifactObservationSendSchedule(clock, Duration.ofMinutes(5));
        schedule.activate(3L);
        schedule.triggerNow(3L);
        assertTrue(schedule.takeDue(3L));
        schedule.triggerNow(3L);
        assertFalse(schedule.takeDue(3L));
        schedule.complete(3L);
        assertFalse(schedule.takeDue(3L));
    }

    @Test
    void rejectsNonPositiveOrSubMillisecondConfiguration() {
        MutableClock clock = new MutableClock(Instant.EPOCH);
        assertThrows(IllegalArgumentException.class,
                () -> new ArtifactObservationSendSchedule(clock, Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> new ArtifactObservationSendSchedule(clock, Duration.ofNanos(1L)));
        ArtifactObservationSendSchedule schedule =
                new ArtifactObservationSendSchedule(clock, Duration.ofSeconds(1));
        assertThrows(IllegalArgumentException.class, () -> schedule.activate(0L));
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
