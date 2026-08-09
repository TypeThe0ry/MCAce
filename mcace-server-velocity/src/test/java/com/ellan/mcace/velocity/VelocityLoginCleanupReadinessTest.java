package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

final class VelocityLoginCleanupReadinessTest {
    @Test
    void readinessRequiresBothExactTicketCleanupAndAbsentProxyPlayer() {
        VelocityLoginCleanupReadiness readiness = new VelocityLoginCleanupReadiness(1_000L);

        assertEquals(VelocityLoginCleanupReadiness.Outcome.PENDING,
                readiness.poll(2_000L, false, true));
        assertEquals(VelocityLoginCleanupReadiness.Outcome.PENDING,
                readiness.poll(2_000L, true, false));
        assertEquals(VelocityLoginCleanupReadiness.Outcome.READY,
                readiness.poll(2_000L, true, true));
    }

    @Test
    void deadlineTerminatesWithFixedContentFreeMarker() {
        long started = 10_000L;
        VelocityLoginCleanupReadiness readiness = new VelocityLoginCleanupReadiness(started);
        long deadline = started + VelocityLoginCleanupReadiness.TIMEOUT.toNanos();

        assertEquals(VelocityLoginCleanupReadiness.Outcome.TIMEOUT,
                readiness.poll(deadline, false, false));
        assertEquals("MCAce LOGIN_CLEANUP_READY", VelocityLoginCleanupReadiness.marker(
                VelocityLoginCleanupReadiness.Outcome.READY));
        assertEquals("MCAce LOGIN_CLEANUP_TIMEOUT", VelocityLoginCleanupReadiness.marker(
                VelocityLoginCleanupReadiness.Outcome.TIMEOUT));
        assertFalse(VelocityLoginCleanupReadiness.READY_MARKER.contains("00000000"));
        assertFalse(VelocityLoginCleanupReadiness.TIMEOUT_MARKER.contains("session"));
    }

    @Test
    void elapsedTimeComparisonSurvivesNanoTimeSignWrap() {
        long started = Long.MAX_VALUE - 10L;
        long timeout = VelocityLoginCleanupReadiness.TIMEOUT.toNanos();
        VelocityLoginCleanupReadiness readiness = new VelocityLoginCleanupReadiness(started);

        assertEquals(VelocityLoginCleanupReadiness.Outcome.PENDING,
                readiness.poll(started + timeout - 1L, false, false));
        assertEquals(VelocityLoginCleanupReadiness.Outcome.TIMEOUT,
                readiness.poll(started + timeout, false, false));
    }

    @Test
    void pollBudgetTerminatesEvenIfSchedulerTimeDoesNotAdvance() {
        VelocityLoginCleanupReadiness readiness = new VelocityLoginCleanupReadiness(7_000L);
        for (int poll = 1; poll < VelocityLoginCleanupReadiness.MAX_POLLS; poll++) {
            assertEquals(VelocityLoginCleanupReadiness.Outcome.PENDING,
                    readiness.poll(7_000L, false, false));
        }
        assertEquals(VelocityLoginCleanupReadiness.Outcome.TIMEOUT,
                readiness.poll(7_000L, false, false));
    }
}
