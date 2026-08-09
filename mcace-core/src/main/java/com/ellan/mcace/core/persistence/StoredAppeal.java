package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.Objects;

public record StoredAppeal(
        AppealDraft draft,
        AppealStatus status,
        String decisionReason,
        long version,
        Instant createdAt,
        Instant updatedAt) {
    public StoredAppeal {
        Objects.requireNonNull(draft, "draft");
        Objects.requireNonNull(status, "status");
        decisionReason = Objects.requireNonNull(decisionReason, "decisionReason");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (version <= 0 || updatedAt.isBefore(createdAt) || decisionReason.length() > 4_096) {
            throw new IllegalArgumentException("invalid stored appeal");
        }
        if ((status == AppealStatus.GRANTED || status == AppealStatus.UPHELD)
                && decisionReason.isBlank()) {
            throw new IllegalArgumentException("a terminal appeal requires a decision reason");
        }
    }
}
