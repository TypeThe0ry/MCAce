package com.ellan.mcace.fabric;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/** Low-frequency, ACK-driven scheduler for optional policy-scoped observation refreshes. */
final class ArtifactObservationSendSchedule {
    private static final long INITIAL_RETRY_BACKOFF_MILLIS = 1_000L;
    private static final long MAX_RETRY_BACKOFF_MILLIS = 30_000L;

    private final Clock clock;
    private final long intervalMillis;
    private long activeAttempt;
    private long nextDueAtMillis;
    private long inFlightSinceMillis;
    private boolean inFlight;
    private boolean awaitingResult;
    private boolean completedOnce;
    private boolean dirty;
    private int consecutiveFailures;

    ArtifactObservationSendSchedule(Clock clock, Duration interval) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.intervalMillis = Objects.requireNonNull(interval, "interval").toMillis();
        if (intervalMillis <= 0L) throw new IllegalArgumentException("observation interval must be positive");
    }

    synchronized void activate(long attempt) {
        if (attempt <= 0L) throw new IllegalArgumentException("attempt must be positive");
        activeAttempt = attempt;
        nextDueAtMillis = saturatedAdd(clock.millis(), intervalMillis);
        inFlightSinceMillis = 0L;
        inFlight = false;
        awaitingResult = false;
        completedOnce = false;
        dirty = false;
        consecutiveFailures = 0;
    }

    synchronized void cancel() {
        activeAttempt = 0L;
        nextDueAtMillis = 0L;
        inFlightSinceMillis = 0L;
        inFlight = false;
        awaitingResult = false;
        completedOnce = false;
        dirty = false;
        consecutiveFailures = 0;
    }

    synchronized boolean isActive(long attempt) {
        return attempt > 0L && activeAttempt == attempt;
    }

    synchronized boolean isInFlight(long attempt) {
        return isActive(attempt) && inFlight;
    }

    synchronized boolean takeDue(long attempt) {
        if (!isActive(attempt) || inFlight || clock.millis() < nextDueAtMillis) return false;
        inFlight = true;
        inFlightSinceMillis = 0L;
        awaitingResult = false;
        return true;
    }

    /**
     * The first observed runtime change is immediate. Once one update is accepted, later changes
     * coalesce behind the full interval; a change can never punch through the cooldown. A failure
     * also keeps its bounded retry deadline even if the state remains visibly dirty.
     */
    synchronized boolean takeDue(long attempt, boolean stateChanged) {
        if (stateChanged && isActive(attempt)) {
            dirty = true;
            if (!completedOnce && consecutiveFailures == 0 && !inFlight) {
                nextDueAtMillis = Math.min(nextDueAtMillis, clock.millis());
            }
        }
        return takeDue(attempt);
    }

    synchronized void triggerNow(long attempt) {
        if (!isActive(attempt)) return;
        dirty = true;
        if (!completedOnce && consecutiveFailures == 0 && !inFlight) {
            nextDueAtMillis = Math.min(nextDueAtMillis, clock.millis());
        }
    }

    /** Starts the ACK timeout only after every fragment has reached the transport API. */
    synchronized void markSent(long attempt) {
        if (isActive(attempt) && inFlight) {
            awaitingResult = true;
            inFlightSinceMillis = clock.millis();
        }
    }

    /** Advances the five-minute contract only after a verified accepted server result. */
    synchronized void complete(long attempt) {
        if (!isActive(attempt)) return;
        inFlight = false;
        awaitingResult = false;
        inFlightSinceMillis = 0L;
        completedOnce = true;
        dirty = false;
        consecutiveFailures = 0;
        nextDueAtMillis = saturatedAdd(clock.millis(), intervalMillis);
    }

    /** Retains a dirty update and retries it with deterministic bounded exponential backoff. */
    synchronized void fail(long attempt) {
        if (!isActive(attempt)) return;
        inFlight = false;
        awaitingResult = false;
        inFlightSinceMillis = 0L;
        dirty = true;
        if (consecutiveFailures < 30) consecutiveFailures++;
        nextDueAtMillis = saturatedAdd(clock.millis(), retryBackoffMillis());
    }

    /** Applies a signed server rate-limit hint without allowing an unbounded scheduling stall. */
    synchronized void retryAt(long attempt, long retryAfterEpochMs) {
        if (!isActive(attempt)) return;
        inFlight = false;
        awaitingResult = false;
        inFlightSinceMillis = 0L;
        dirty = true;
        if (consecutiveFailures < 30) consecutiveFailures++;
        long now = clock.millis();
        long earliest = saturatedAdd(now, retryBackoffMillis());
        long latest = saturatedAdd(now, intervalMillis);
        nextDueAtMillis = Math.max(earliest, Math.min(retryAfterEpochMs, latest));
    }

    /** Releases an ACK-waiting transfer after a bounded timeout while preserving it for retry. */
    synchronized boolean timeoutIfDue(long attempt, Duration timeout) {
        long timeoutMillis = Objects.requireNonNull(timeout, "timeout").toMillis();
        if (timeoutMillis <= 0L) throw new IllegalArgumentException("observation ACK timeout must be positive");
        if (!isActive(attempt) || !inFlight || !awaitingResult
                || elapsedMillis(clock.millis(), inFlightSinceMillis) < timeoutMillis) {
            return false;
        }
        fail(attempt);
        return true;
    }

    private long retryBackoffMillis() {
        int exponent = Math.max(0, Math.min(consecutiveFailures - 1, 30));
        long candidate = INITIAL_RETRY_BACKOFF_MILLIS << exponent;
        return Math.min(intervalMillis, Math.min(MAX_RETRY_BACKOFF_MILLIS, candidate));
    }

    private static long elapsedMillis(long now, long then) {
        if (now < then) return 0L;
        long elapsed = now - then;
        return elapsed < 0L ? Long.MAX_VALUE : elapsed;
    }

    private static long saturatedAdd(long value, long increment) {
        if (increment < 0L) throw new IllegalArgumentException("increment must not be negative");
        return value > Long.MAX_VALUE - increment ? Long.MAX_VALUE : value + increment;
    }
}
