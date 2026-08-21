package com.ellan.mcace.fabric;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/** Low-frequency scheduler for optional policy-scoped observation refreshes. */
final class ArtifactObservationSendSchedule {
    private final Clock clock;
    private final long intervalMillis;
    private long activeAttempt;
    private long nextDueAtMillis;
    private boolean inFlight;

    ArtifactObservationSendSchedule(Clock clock, Duration interval) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.intervalMillis = Objects.requireNonNull(interval, "interval").toMillis();
        if (intervalMillis <= 0L) throw new IllegalArgumentException("observation interval must be positive");
    }

    synchronized void activate(long attempt) {
        if (attempt <= 0L) throw new IllegalArgumentException("attempt must be positive");
        activeAttempt = attempt;
        nextDueAtMillis = Math.addExact(clock.millis(), intervalMillis);
        inFlight = false;
    }

    synchronized void cancel() { activeAttempt = 0L; nextDueAtMillis = 0L; inFlight = false; }
    synchronized boolean isActive(long attempt) { return attempt > 0L && activeAttempt == attempt; }
    synchronized boolean takeDue(long attempt) {
        if (!isActive(attempt) || inFlight || clock.millis() < nextDueAtMillis) return false;
        inFlight = true;
        return true;
    }
    synchronized void complete(long attempt) {
        if (isActive(attempt) && inFlight) {
            inFlight = false;
            nextDueAtMillis = Math.addExact(clock.millis(), intervalMillis);
        }
    }
}
