package com.ellan.mcace.core.trust;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/** Immutable, explainable result of the deterministic client trust state machine. */
public record ClientTrustAssessment(
        ClientTrustState state,
        List<String> reasons,
        Instant evaluatedAt) {
    public ClientTrustAssessment {
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(reasons, "reasons");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        reasons = List.copyOf(reasons);
        if (reasons.isEmpty()) throw new IllegalArgumentException("trust assessment needs a reason");
    }
}
