package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.Objects;

public record StoredReviewCase(
        ReviewCaseDraft draft,
        ReviewStatus status,
        String recommendation,
        String resolution,
        long version,
        Instant createdAt,
        Instant updatedAt) {
    public StoredReviewCase {
        Objects.requireNonNull(draft, "draft");
        Objects.requireNonNull(status, "status");
        recommendation = Objects.requireNonNull(recommendation, "recommendation");
        resolution = Objects.requireNonNull(resolution, "resolution");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (version <= 0 || updatedAt.isBefore(createdAt)
                || recommendation.length() > 1_024 || resolution.length() > 4_096) {
            throw new IllegalArgumentException("invalid stored review case");
        }
        if (status == ReviewStatus.ACTION_RECOMMENDED && recommendation.isBlank()) {
            throw new IllegalArgumentException("an action recommendation requires explanatory text");
        }
    }
}
