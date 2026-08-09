package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface CloudControlPlaneStore extends SecurityAuditSink {
    void checkHealth() throws SecurityPersistenceException;

    StoredRevocation appendRevocation(RevocationDraft revocation, OperatorAuditRecord audit)
            throws SecurityPersistenceException;

    List<StoredRevocation> findRevocationsAfter(long sequence, Instant activeAt, int limit)
            throws SecurityPersistenceException;

    void appendOperatorAudit(OperatorAuditRecord audit) throws SecurityPersistenceException;

    StoredReviewCase createReviewCase(ReviewCaseDraft draft, OperatorAuditRecord audit)
            throws SecurityPersistenceException;

    StoredReviewCase transitionReviewCase(ReviewTransition transition, OperatorAuditRecord audit)
            throws SecurityPersistenceException;

    StoredAppeal createAppeal(AppealDraft draft, OperatorAuditRecord audit)
            throws SecurityPersistenceException;

    StoredAppeal transitionAppeal(AppealTransition transition, OperatorAuditRecord audit)
            throws SecurityPersistenceException;

    PlayerTimeline findPlayerTimeline(UUID playerId, int limit) throws SecurityPersistenceException;

    StoredRiskPolicyRelease createRiskPolicyRelease(
            RiskPolicyReleaseDraft draft, OperatorAuditRecord audit) throws SecurityPersistenceException;

    StoredPolicyRollout appendPolicyRollout(
            PolicyRolloutDraft draft, OperatorAuditRecord audit) throws SecurityPersistenceException;

    List<StoredRiskPolicyRelease> findRiskPolicyReleases(int limit) throws SecurityPersistenceException;

    List<StoredPolicyRollout> findPolicyRolloutsAfter(long sequence, int limit)
            throws SecurityPersistenceException;

    RiskPolicyDeployment findRiskPolicyDeployment() throws SecurityPersistenceException;

    void appendCloudRiskEvent(RiskEventAuditRecord event, RiskPolicyEvaluation evaluation)
            throws SecurityPersistenceException;

    void appendRiskFeedback(RiskFeedbackDraft feedback, OperatorAuditRecord audit)
            throws SecurityPersistenceException;

    PolicyMetrics policyMetrics(String policyVersion, Instant from, Instant to)
            throws SecurityPersistenceException;
}
