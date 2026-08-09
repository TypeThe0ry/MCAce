package com.ellan.mcace.velocity;

import java.time.Duration;
import java.util.Objects;

/** Pure state machine used by the scheduler-driven, non-blocking disconnect cleanup probe. */
final class VelocityLoginCleanupReadiness {
    static final String READY_MARKER = "MCAce LOGIN_CLEANUP_READY";
    static final String TIMEOUT_MARKER = "MCAce LOGIN_CLEANUP_TIMEOUT";
    static final Duration POLL_INTERVAL = Duration.ofMillis(25);
    static final Duration TIMEOUT = Duration.ofSeconds(5);
    static final int MAX_POLLS = 256;

    enum Outcome { PENDING, READY, TIMEOUT }

    private final long startedNanos;
    private int polls;

    VelocityLoginCleanupReadiness(long startedNanos) {
        this.startedNanos = startedNanos;
    }

    synchronized Outcome poll(long nowNanos, boolean exactTicketCleared, boolean proxyPlayerAbsent) {
        if (exactTicketCleared && proxyPlayerAbsent) return Outcome.READY;
        polls++;
        // System.nanoTime is only meaningful as a subtraction. The five-second interval is far
        // below half the signed range, so this remains correct across its sign-bit wrap.
        return polls >= MAX_POLLS || nowNanos - startedNanos >= TIMEOUT.toNanos()
                ? Outcome.TIMEOUT : Outcome.PENDING;
    }

    static String marker(Outcome outcome) {
        return switch (Objects.requireNonNull(outcome, "outcome")) {
            case READY -> READY_MARKER;
            case TIMEOUT -> TIMEOUT_MARKER;
            case PENDING -> throw new IllegalArgumentException("pending cleanup has no terminal marker");
        };
    }
}
