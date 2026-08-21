package com.ellan.mcace.fabric;

import java.util.concurrent.atomic.AtomicLong;

/** Monotonic cancellation gate so a prior connection's async scan can never send later. */
final class AuthenticationAttemptGate {
    private final AtomicLong generation = new AtomicLong();
    private final AtomicLong activeAttempt = new AtomicLong();

    long begin() {
        long next = generation.incrementAndGet();
        activeAttempt.set(next);
        return next;
    }

    void cancel() {
        activeAttempt.set(0);
        generation.incrementAndGet();
    }

    boolean isActive(long attempt) {
        return attempt > 0 && activeAttempt.get() == attempt;
    }

    long activeAttempt() {
        return activeAttempt.get();
    }
}
