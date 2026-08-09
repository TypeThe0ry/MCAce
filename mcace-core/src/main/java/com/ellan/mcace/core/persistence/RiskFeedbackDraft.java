package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record RiskFeedbackDraft(
        UUID feedbackId,
        UUID eventId,
        UUID reviewCaseId,
        RiskFeedbackLabel label,
        String notes,
        String actorId,
        Instant occurredAt) {
    public RiskFeedbackDraft {
        Objects.requireNonNull(feedbackId, "feedbackId");
        Objects.requireNonNull(eventId, "eventId");
        Objects.requireNonNull(reviewCaseId, "reviewCaseId");
        Objects.requireNonNull(label, "label");
        notes = ReviewCaseDraft.requireText(notes, "notes", 4_096);
        actorId = ReviewCaseDraft.requireText(actorId, "actorId", 128);
        Objects.requireNonNull(occurredAt, "occurredAt");
    }
}
