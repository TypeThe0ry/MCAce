package com.ellan.mcace.core.persistence;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

public record PlayerTimeline(
        UUID playerId,
        List<SessionAuditRecord> sessions,
        List<RiskEventAuditRecord> riskEvents,
        List<RiskPolicyEvaluation> policyEvaluations,
        List<StoredEvidenceMetadata> evidence,
        List<StoredReviewCase> reviews,
        List<StoredAppeal> appeals,
        List<WorkflowTimelineEvent> workflowEvents) {
    public PlayerTimeline {
        Objects.requireNonNull(playerId, "playerId");
        sessions = List.copyOf(sessions);
        riskEvents = List.copyOf(riskEvents);
        policyEvaluations = List.copyOf(policyEvaluations);
        evidence = List.copyOf(evidence);
        reviews = List.copyOf(reviews);
        appeals = List.copyOf(appeals);
        workflowEvents = List.copyOf(workflowEvents);
    }
}
