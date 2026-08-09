package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.Objects;

public record StoredPolicyRollout(long sequence, PolicyRolloutDraft draft, Instant createdAt) {
    public StoredPolicyRollout {
        if (sequence <= 0) throw new IllegalArgumentException("sequence must be positive");
        Objects.requireNonNull(draft, "draft");
        Objects.requireNonNull(createdAt, "createdAt");
    }
}
