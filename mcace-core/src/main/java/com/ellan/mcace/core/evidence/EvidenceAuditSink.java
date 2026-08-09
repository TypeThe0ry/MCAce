package com.ellan.mcace.core.evidence;

/** Bounded, content-free evidence audit handoff. */
@FunctionalInterface
public interface EvidenceAuditSink {
    void append(EvidenceAuditRecord record);

    default void appendDeletion(EvidenceDeletionAuditRecord record) { }

    default void appendReview(EvidenceReviewAuditRecord record) { }

    static EvidenceAuditSink noop() { return ignored -> { }; }
}
