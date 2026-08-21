package com.ellan.mcace.fabric;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/**
 * Small, thread-safe tick scheduler for already authenticated heartbeats.
 * It only decides when a sender may run; hashing, signing, filesystem work, and networking stay
 * outside the tick callback.
 */
final class HeartbeatSendSchedule {
    private final Clock clock;
    private final long intervalMillis;
    private long activeAttempt;
    private long nextDueAtMillis;
    private boolean inFlight;

    HeartbeatSendSchedule(Clock clock, Duration interval) {
        this.clock = Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(interval, "interval");
        if (interval.isZero() || interval.isNegative()) {
            throw new IllegalArgumentException("heartbeat interval must be positive");
        }
        this.intervalMillis = interval.toMillis();
        if (intervalMillis <= 0) {
            throw new IllegalArgumentException("heartbeat interval must have millisecond precision");
        }
    }

    synchronized void activate(long attempt) {
        if (attempt <= 0) {
            throw new IllegalArgumentException("authentication attempt must be positive");
        }
        activeAttempt = attempt;
        nextDueAtMillis = Math.addExact(clock.millis(), intervalMillis);
        inFlight = false;
    }

    synchronized void cancel() {
        activeAttempt = 0;
        nextDueAtMillis = 0;
        inFlight = false;
    }

    synchronized boolean isActive(long attempt) {
        return attempt > 0 && activeAttempt == attempt;
    }

    /** Returns true once per elapsed interval and advances without catch-up bursts. */
    synchronized boolean takeDue(long attempt) {
        if (!isActive(attempt) || inFlight || clock.millis() < nextDueAtMillis) {
            return false;
        }
        inFlight = true;
        return true;
    }

    /** Marks the client-executor send complete and starts the next low-frequency interval. */
    synchronized void complete(long attempt) {
        if (!isActive(attempt) || !inFlight) {
            return;
        }
        inFlight = false;
        nextDueAtMillis = Math.addExact(clock.millis(), intervalMillis);
    }
}
