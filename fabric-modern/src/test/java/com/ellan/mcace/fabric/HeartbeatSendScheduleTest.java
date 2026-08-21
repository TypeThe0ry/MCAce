package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

final class HeartbeatSendScheduleTest {
    @Test
    void sendsOnlyAfterIntervalAndNeverCatchesUpInBursts() {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-08T08:00:00Z"));
        HeartbeatSendSchedule schedule = new HeartbeatSendSchedule(clock, Duration.ofSeconds(30));

        schedule.activate(4);
        assertFalse(schedule.takeDue(4));
        clock.advance(Duration.ofSeconds(30));
        assertTrue(schedule.takeDue(4));
        assertFalse(schedule.takeDue(4));
        schedule.complete(4);
        clock.advance(Duration.ofMinutes(2));
        assertTrue(schedule.takeDue(4));
        assertFalse(schedule.takeDue(4));
    }

    @Test
    void cancelOrSupersedingAttemptPreventsSending() {
        MutableClock clock = new MutableClock(Instant.EPOCH);
        HeartbeatSendSchedule schedule = new HeartbeatSendSchedule(clock, Duration.ofSeconds(30));

        schedule.activate(1);
        schedule.cancel();
        clock.advance(Duration.ofMinutes(1));
        assertFalse(schedule.takeDue(1));
        schedule.activate(2);
        assertFalse(schedule.takeDue(1));
        clock.advance(Duration.ofSeconds(30));
        assertTrue(schedule.takeDue(2));
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
