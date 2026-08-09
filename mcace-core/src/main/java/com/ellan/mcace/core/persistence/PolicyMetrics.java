package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.Objects;

public record PolicyMetrics(
        String policyVersion,
        Instant from,
        Instant to,
        long evaluatedEvents,
        long appliedEvents,
        long shadowEvents,
        long corroboratedEvents,
        long labeledEvents,
        long confirmedSignals,
        long falsePositives,
        long inconclusive) {
    public PolicyMetrics {
        policyVersion = ReviewCaseDraft.requireText(policyVersion, "policyVersion", 64);
        Objects.requireNonNull(from, "from");
        Objects.requireNonNull(to, "to");
        if (!to.isAfter(from) || evaluatedEvents < 0 || appliedEvents < 0 || shadowEvents < 0
                || corroboratedEvents < 0 || labeledEvents < 0 || confirmedSignals < 0
                || falsePositives < 0 || inconclusive < 0) {
            throw new IllegalArgumentException("invalid policy metrics");
        }
    }
}
