package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record WorkflowTimelineEvent(
        UUID eventId,
        UUID playerId,
        String kind,
        UUID subjectId,
        String fromStatus,
        String toStatus,
        String actorId,
        String reason,
        String recommendation,
        Instant occurredAt) {
    public WorkflowTimelineEvent {
        Objects.requireNonNull(eventId, "eventId");
        Objects.requireNonNull(playerId, "playerId");
        kind = ReviewCaseDraft.requireText(kind, "kind", 64);
        Objects.requireNonNull(subjectId, "subjectId");
        fromStatus = Objects.requireNonNull(fromStatus, "fromStatus");
        toStatus = ReviewCaseDraft.requireText(toStatus, "toStatus", 64);
        actorId = ReviewCaseDraft.requireText(actorId, "actorId", 128);
        reason = ReviewCaseDraft.requireText(reason, "reason", 8_192);
        recommendation = Objects.requireNonNull(recommendation, "recommendation");
        Objects.requireNonNull(occurredAt, "occurredAt");
        if (fromStatus.length() > 64 || recommendation.length() > 1_024) {
            throw new IllegalArgumentException("invalid workflow timeline event");
        }
    }
}
