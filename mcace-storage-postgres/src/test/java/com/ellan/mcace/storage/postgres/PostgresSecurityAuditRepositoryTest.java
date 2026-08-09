package com.ellan.mcace.storage.postgres;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.persistence.EvidenceMetadataDraft;
import com.ellan.mcace.core.persistence.AuditAnchorPublication;
import com.ellan.mcace.core.persistence.AppealDraft;
import com.ellan.mcace.core.persistence.AppealStatus;
import com.ellan.mcace.core.persistence.AppealTransition;
import com.ellan.mcace.core.persistence.ObservationOrigin;
import com.ellan.mcace.core.persistence.OperatorAuditRecord;
import com.ellan.mcace.core.persistence.PolicyRolloutDraft;
import com.ellan.mcace.core.persistence.PolicyRolloutStage;
import com.ellan.mcace.core.persistence.RevocationDraft;
import com.ellan.mcace.core.persistence.RevocationSignatureCodec;
import com.ellan.mcace.core.persistence.RevocationSubjectType;
import com.ellan.mcace.core.persistence.RiskEventAuditRecord;
import com.ellan.mcace.core.persistence.RiskFeedbackDraft;
import com.ellan.mcace.core.persistence.RiskFeedbackLabel;
import com.ellan.mcace.core.persistence.RiskPolicyEvaluation;
import com.ellan.mcace.core.persistence.RiskPolicyReleaseDraft;
import com.ellan.mcace.core.persistence.ReviewCaseDraft;
import com.ellan.mcace.core.persistence.ReviewStatus;
import com.ellan.mcace.core.persistence.ReviewTransition;
import com.ellan.mcace.core.persistence.SecurityPersistenceException;
import com.ellan.mcace.core.persistence.SessionAuditRecord;
import com.ellan.mcace.core.persistence.StoredRevocation;
import com.ellan.mcace.core.persistence.StoredAuditAnchor;
import com.ellan.mcace.core.persistence.StoredWebSession;
import com.ellan.mcace.core.persistence.WebPrincipalType;
import com.ellan.mcace.core.persistence.WebRole;
import com.ellan.mcace.core.persistence.WebSessionHandoff;
import com.ellan.mcace.core.persistence.WorkflowConflictException;
import com.ellan.mcace.core.risk.RiskEventType;
import com.ellan.mcace.core.risk.RiskPolicy;
import com.ellan.mcace.core.session.SessionStage;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.EvidenceType;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.RiskBand;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.net.URI;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Callable;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers(disabledWithoutDocker = true)
final class PostgresSecurityAuditRepositoryTest {
    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.6-alpine")
            .withDatabaseName("mcace_test")
            .withUsername("mcace")
            .withPassword("integration-only-password");
    private static final Instant NOW = Instant.parse("2026-08-08T08:00:00Z");
    private static DataSource dataSource;
    private static PostgresSecurityAuditRepository repository;
    private static KeyPair evidenceKeys;

    @BeforeAll
    static void initialize() throws Exception {
        dataSource = PostgresDataSources.create(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        PostgresSchemaMigrator.migrate(dataSource);
        PostgresSchemaMigrator.migrate(dataSource);
        evidenceKeys = Ed25519Keys.generate(new SecureRandom());
        repository = new PostgresSecurityAuditRepository(
                dataSource,
                new Ed25519EvidenceChainSigner(evidenceKeys.getPrivate(), evidenceKeys.getPublic()),
                new Ed25519RevocationSigner(evidenceKeys.getPrivate(), evidenceKeys.getPublic()),
                new Ed25519AuditAnchorSigner(evidenceKeys.getPrivate(), evidenceKeys.getPublic()),
                Clock.fixed(NOW.plusSeconds(60), ZoneOffset.UTC));
    }

    @Test
    void persistsSessionsEventsAndConcurrentAppendOnlyEvidenceChain() throws Exception {
        UUID playerId = UUID.randomUUID();
        SessionAuditRecord session = session(playerId);
        repository.upsertSession(session);
        repository.upsertSession(new SessionAuditRecord(
                session.sessionId(), playerId, session.serverId(), session.policyVersion(), session.policySequence(),
                SessionStage.AUTHENTICATED, TrustLevel.VERIFIED, AdmissionStatus.VERIFIED, 0, RiskBand.NORMAL,
                "fabric-phase2-dev", "1.21.1", LoaderType.FABRIC,
                session.startedAt(), NOW.plusSeconds(10), session.expiresAt()));
        RiskEventAuditRecord risk = new RiskEventAuditRecord(
                UUID.randomUUID(), session.sessionId(), playerId, RiskEventType.UNKNOWN_MOD, 15,
                "integration-controlled", ObservationOrigin.CLIENT_REPORTED, false, NOW.plusSeconds(5),
                "{\"fixture\":true}");
        repository.appendRiskEvent(risk);

        List<Future<?>> futures = new ArrayList<>();
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int index = 0; index < 8; index++) {
                int fixture = index;
                futures.add(executor.submit(() -> repository.appendEvidence(evidence(playerId, fixture))));
            }
            for (Future<?> future : futures) future.get();
        }

        assertEquals(SessionStage.AUTHENTICATED,
                repository.findSession(session.sessionId()).orElseThrow().stage());
        List<RiskEventAuditRecord> storedRisk = repository.findRiskEvents(playerId);
        assertEquals(1, storedRisk.size());
        assertEquals(risk.eventId(), storedRisk.getFirst().eventId());
        assertEquals(risk.type(), storedRisk.getFirst().type());
        assertTrue(storedRisk.getFirst().detailsJson().contains("\"fixture\""));
        assertEquals(8, repository.findEvidence().size());
        EvidenceChainVerification verification = repository.verifyEvidenceChain(
                Map.of(new Ed25519EvidenceChainSigner(
                        evidenceKeys.getPrivate(), evidenceKeys.getPublic()).keyId(), evidenceKeys.getPublic()));
        assertTrue(verification.valid(), verification.reason());
        assertEquals(8, verification.verifiedEntries());

        RevocationDraft revocation = new RevocationDraft(
                UUID.randomUUID(), RevocationSubjectType.CLIENT_BUILD, "fabric-compromised-build",
                "OPERATOR_REVIEW_CONFIRMED", NOW, null, "integration-operator");
        OperatorAuditRecord audit = new OperatorAuditRecord(
                UUID.randomUUID(), "integration-operator", "REVOCATION_CREATED",
                "CLIENT_BUILD", revocation.subjectId(), NOW, "{\"ticket\":\"SEC-42\"}");
        StoredRevocation storedRevocation = repository.appendRevocation(revocation, audit);
        assertEquals(1, storedRevocation.sequence());
        assertTrue(RevocationSignatureCodec.verify(storedRevocation, evidenceKeys.getPublic()));
        assertEquals(1, repository.findRevocationsAfter(0, NOW.plusSeconds(1), 100).size());
        assertEquals(1, scalarLong(
                "SELECT count(*) FROM mcace_operator_audit WHERE action = 'REVOCATION_CREATED'"));

        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            assertThrows(SQLException.class,
                    () -> statement.executeUpdate("UPDATE mcace_evidence_metadata SET operator_id = 'tampered'"));
            assertThrows(SQLException.class,
                    () -> statement.executeUpdate("DELETE FROM mcace_risk_events"));
            assertThrows(SQLException.class,
                    () -> statement.executeUpdate("TRUNCATE mcace_evidence_metadata"));
            assertThrows(SQLException.class,
                    () -> statement.executeUpdate("DELETE FROM mcace_revocations"));
            assertThrows(SQLException.class,
                    () -> statement.executeUpdate("UPDATE mcace_operator_audit SET actor_id = 'tampered'"));
        }
        assertEquals(7, scalarLong("SELECT count(*) FROM mcace_schema_migrations"));
    }

    @Test
    void createsSignedChainedAnchorsAndLeasesPublicationAcrossInstances() throws Exception {
        List<Future<Optional<StoredAuditAnchor>>> creations = new ArrayList<>();
        try (var executor = Executors.newFixedThreadPool(2)) {
            creations.add(executor.submit(() -> repository.createAuditAnchor(Duration.ofMinutes(5))));
            creations.add(executor.submit(() -> repository.createAuditAnchor(Duration.ofMinutes(5))));
            List<StoredAuditAnchor> created = new ArrayList<>();
            for (Future<Optional<StoredAuditAnchor>> creation : creations) {
                creation.get().ifPresent(created::add);
            }
            assertEquals(1, created.size());
        }
        StoredAuditAnchor first = repository.claimPendingAuditAnchors(
                "anchor-worker-a", Duration.ofMinutes(1), 10).getFirst();
        assertEquals(1, first.sequence());
        assertTrue(AuditAnchorCodec.verify(first, evidenceKeys.getPublic()));
        assertArrayEquals(new byte[32], first.previousAnchorSha256());
        assertTrue(repository.claimPendingAuditAnchors(
                "anchor-worker-b", Duration.ofMinutes(1), 10).isEmpty());

        repository.releaseAuditAnchorClaim(
                first.anchorId(), "anchor-worker-a", Duration.ZERO, "controlled network failure");
        StoredAuditAnchor reclaimed = repository.claimPendingAuditAnchors(
                "anchor-worker-b", Duration.ofMinutes(1), 10).getFirst();
        assertEquals(first.anchorId(), reclaimed.anchorId());
        repository.recordAuditAnchorPublication(
                first.anchorId(), "anchor-worker-b",
                new AuditAnchorPublication(
                        URI.create("https://anchor.example.test/v1/heads"), NOW.plusSeconds(61),
                        "receipt-1", java.security.MessageDigest.getInstance("SHA-256")
                                .digest("receipt".getBytes(java.nio.charset.StandardCharsets.UTF_8))));
        assertTrue(repository.claimPendingAuditAnchors(
                "anchor-worker-c", Duration.ofMinutes(1), 10).isEmpty());

        StoredAuditAnchor second = repository.createAuditAnchor(Duration.ZERO).orElseThrow();
        assertEquals(2, second.sequence());
        assertArrayEquals(first.anchorSha256(), second.previousAnchorSha256());
        assertTrue(AuditAnchorCodec.verify(second, evidenceKeys.getPublic()));
        assertEquals(2, scalarLong("SELECT count(*) FROM mcace_audit_anchors"));
        assertEquals(1, scalarLong("SELECT count(*) FROM mcace_audit_anchor_publications"));

        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            assertThrows(SQLException.class, () -> statement.executeUpdate(
                    "UPDATE mcace_audit_anchors SET signer_key_id = 'tampered'"));
            assertThrows(SQLException.class, () -> statement.executeUpdate(
                    "DELETE FROM mcace_audit_anchor_publications"));
        }
    }

    @Test
    void atomicallyConsumesWebHandoffsAndEnforcesPlayerNotificationOwnership() throws Exception {
        UUID playerId = UUID.randomUUID();
        UUID handoffId = UUID.randomUUID();
        byte[] handoffHash = java.security.MessageDigest.getInstance("SHA-256")
                .digest("one-time-handoff".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        repository.createWebHandoff(new WebSessionHandoff(
                handoffId, handoffHash, WebPrincipalType.PLAYER, playerId.toString(),
                Set.of(WebRole.PLAYER), "/appeal", "velocity:integration",
                NOW, NOW.plusSeconds(90)));

        List<Future<Optional<WebSessionHandoff>>> consumptions = new ArrayList<>();
        try (var executor = Executors.newFixedThreadPool(2)) {
            consumptions.add(executor.submit(() -> repository.consumeWebHandoff(handoffId)));
            consumptions.add(executor.submit(() -> repository.consumeWebHandoff(handoffId)));
            int successes = 0;
            for (Future<Optional<WebSessionHandoff>> result : consumptions) {
                if (result.get().isPresent()) successes++;
            }
            assertEquals(1, successes);
        }

        byte[] sessionHash = java.security.MessageDigest.getInstance("SHA-256")
                .digest("opaque-session".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        StoredWebSession webSession = new StoredWebSession(
                UUID.randomUUID(), sessionHash, WebPrincipalType.PLAYER, playerId.toString(),
                Set.of(WebRole.PLAYER), "velocity:integration", NOW, NOW.plus(Duration.ofHours(2)));
        repository.createWebSession(webSession);
        assertEquals(webSession.sessionId(),
                repository.findActiveWebSession(sessionHash, NOW.plusSeconds(1)).orElseThrow().sessionId());
        assertTrue(repository.findActiveWebSession(new byte[32], NOW.plusSeconds(1)).isEmpty());

        UUID caseId = UUID.randomUUID();
        repository.createReviewCase(new ReviewCaseDraft(
                        caseId, playerId, "Portal ownership fixture",
                        "This case validates notification ownership.", "review-portal"),
                audit("review-portal", "REVIEW_CREATED", "REVIEW_CASE", caseId));
        var notifications = repository.findPlayerNotifications(playerId, 20);
        assertEquals(1, notifications.size());
        assertEquals("REVIEW_OPENED", notifications.getFirst().type());
        assertTrue(!notifications.getFirst().read());

        UUID otherPlayer = UUID.randomUUID();
        assertTrue(repository.findPlayerNotifications(otherPlayer, 20).isEmpty());
        repository.markPlayerNotificationRead(
                otherPlayer, notifications.getFirst().notificationId(), NOW.plusSeconds(61));
        assertTrue(!repository.findPlayerNotifications(playerId, 20).getFirst().read());
        repository.markPlayerNotificationRead(
                playerId, notifications.getFirst().notificationId(), NOW.plusSeconds(61));
        assertTrue(repository.findPlayerNotifications(playerId, 20).getFirst().read());

        assertThrows(WorkflowConflictException.class, () -> repository.transitionReviewCase(
                new ReviewTransition(caseId, 99, ReviewStatus.UNDER_REVIEW,
                        "stale write must not notify", "", "review-portal"),
                audit("review-portal", "REVIEW_TRANSITIONED", "REVIEW_CASE", caseId)));
        assertEquals(1, repository.findPlayerNotifications(playerId, 20).size());

        repository.deleteWebSession(webSession.sessionId(), sessionHash);
        assertTrue(repository.findActiveWebSession(sessionHash, NOW.plusSeconds(1)).isEmpty());
    }

    @Test
    void versionsStagesRollsBackAndMeasuresRiskPoliciesWithoutAutomaticEnforcement() throws Exception {
        UUID playerId = UUID.randomUUID();
        UUID policyId = UUID.randomUUID();
        RiskPolicyReleaseDraft release = policyRelease(
                policyId, "phase3-policy-test-" + policyId.toString().substring(0, 8), 27);
        var storedRelease = repository.createRiskPolicyRelease(release, audit(
                "policy-operator", "RISK_POLICY_CREATED", "RISK_POLICY", policyId));
        assertEquals(release.policy().version(), storedRelease.draft().policy().version());
        assertEquals(32, storedRelease.releaseSha256().length);

        UUID invalidRolloutId = UUID.randomUUID();
        assertThrows(WorkflowConflictException.class, () -> repository.appendPolicyRollout(
                new PolicyRolloutDraft(
                        invalidRolloutId, policyId, PolicyRolloutStage.CANARY, 10,
                        "cannot skip shadow", "policy-operator"),
                audit("policy-operator", "POLICY_ROLLOUT_APPENDED", "POLICY_ROLLOUT", invalidRolloutId)));

        UUID shadowId = UUID.randomUUID();
        repository.appendPolicyRollout(new PolicyRolloutDraft(
                shadowId, policyId, PolicyRolloutStage.SHADOW, 0,
                "measure candidate without assignment", "policy-operator"),
                audit("policy-operator", "POLICY_ROLLOUT_APPENDED", "POLICY_ROLLOUT", shadowId));
        var shadowDeployment = repository.findRiskPolicyDeployment();
        assertEquals(PolicyRolloutStage.SHADOW, shadowDeployment.stage());
        assertEquals(RiskPolicy.defaults().version(), shadowDeployment.baseline().version());
        assertEquals(release.policy().version(), shadowDeployment.candidate().version());

        UUID eventId = UUID.randomUUID();
        RiskEventAuditRecord risk = new RiskEventAuditRecord(
                eventId, "", playerId, RiskEventType.UNKNOWN_MOD, 15,
                "policy-integration", ObservationOrigin.SERVER_CONFIRMED, true,
                NOW.plusSeconds(61), "{\"fixture\":\"shadow\"}");
        repository.appendCloudRiskEvent(risk, new RiskPolicyEvaluation(
                eventId, RiskPolicy.defaults().version(), RiskPolicy.defaults().version(),
                release.policy().version(), 15, 15, 27, shadowId,
                PolicyRolloutStage.SHADOW, 42, NOW.plusSeconds(61)));

        UUID caseId = UUID.randomUUID();
        repository.createReviewCase(new ReviewCaseDraft(
                caseId, playerId, "Policy false-positive fixture",
                "Known-good replay must be linked before feedback", "review-portal"),
                audit("review-portal", "REVIEW_CREATED", "REVIEW_CASE", caseId));
        UUID prematureFeedbackId = UUID.randomUUID();
        assertThrows(WorkflowConflictException.class, () -> repository.appendRiskFeedback(
                new RiskFeedbackDraft(
                        prematureFeedbackId, eventId, caseId, RiskFeedbackLabel.FALSE_POSITIVE,
                        "an open review cannot establish a false positive",
                        "review-portal", NOW.plusSeconds(62)),
                audit("review-portal", "RISK_FEEDBACK_RECORDED", "RISK_FEEDBACK", prematureFeedbackId)));
        repository.transitionReviewCase(new ReviewTransition(
                caseId, 1, ReviewStatus.CLOSED_NO_ACTION,
                "known-good replay reproduced the observation", "", "review-portal"),
                audit("review-portal", "REVIEW_TRANSITIONED", "REVIEW_CASE", caseId));
        UUID feedbackId = UUID.randomUUID();
        repository.appendRiskFeedback(new RiskFeedbackDraft(
                feedbackId, eventId, caseId, RiskFeedbackLabel.FALSE_POSITIVE,
                "controlled known-good replay reproduced the observation",
                "review-portal", NOW.plusSeconds(62)),
                audit("review-portal", "RISK_FEEDBACK_RECORDED", "RISK_FEEDBACK", feedbackId));
        var metrics = repository.policyMetrics(
                release.policy().version(), NOW, NOW.plusSeconds(120));
        assertEquals(1, metrics.evaluatedEvents());
        assertEquals(0, metrics.appliedEvents());
        assertEquals(1, metrics.shadowEvents());
        assertEquals(1, metrics.falsePositives());

        UUID canaryId = UUID.randomUUID();
        repository.appendPolicyRollout(new PolicyRolloutDraft(
                canaryId, policyId, PolicyRolloutStage.CANARY, 10,
                "bounded canary", "policy-operator"),
                audit("policy-operator", "POLICY_ROLLOUT_APPENDED", "POLICY_ROLLOUT", canaryId));
        UUID rollbackId = UUID.randomUUID();
        repository.appendPolicyRollout(new PolicyRolloutDraft(
                rollbackId, policyId, PolicyRolloutStage.ROLLED_BACK, 0,
                "false-positive fixture exceeded the rollout guardrail", "policy-operator"),
                audit("policy-operator", "POLICY_ROLLOUT_APPENDED", "POLICY_ROLLOUT", rollbackId));
        assertEquals(PolicyRolloutStage.ROLLED_BACK, repository.findRiskPolicyDeployment().stage());
        assertEquals(RiskPolicy.defaults().version(), repository.findRiskPolicyDeployment().baseline().version());

        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            assertThrows(SQLException.class, () -> statement.executeUpdate("""
                    INSERT INTO mcace_policy_rollouts(
                        sequence, rollout_id, policy_id, stage, percentage, reason, created_by, created_at)
                    VALUES (nextval('mcace_policy_rollout_sequence'), '%s', '%s', 'SHADOW', 0,
                            'terminal bypass fixture', 'direct-sql', clock_timestamp())
                    """.formatted(UUID.randomUUID(), policyId)));
            assertThrows(SQLException.class, () -> statement.executeUpdate(
                    "UPDATE mcace_risk_policy_releases SET description = 'tampered' WHERE policy_id = '"
                            + policyId + "'"));
            assertThrows(SQLException.class, () -> statement.executeUpdate(
                    "DELETE FROM mcace_policy_rollouts WHERE policy_id = '" + policyId + "'"));
            assertThrows(SQLException.class, () -> statement.executeUpdate(
                    "UPDATE mcace_risk_feedback SET label = 'CONFIRMED_SIGNAL' WHERE feedback_id = '"
                            + feedbackId + "'"));
        }
    }

    @Test
    void enforcesReviewAppealStateMachinesOptimisticConcurrencyAndTimelineProvenance() throws Exception {
        UUID playerId = UUID.randomUUID();
        UUID caseId = UUID.randomUUID();
        ReviewCaseDraft draft = new ReviewCaseDraft(
                caseId, playerId, "Correlated security observation",
                "A reviewer must evaluate server and client provenance", "review-portal");
        var opened = repository.createReviewCase(draft, audit(
                "review-portal", "REVIEW_CREATED", "REVIEW_CASE", caseId));
        assertEquals(ReviewStatus.OPEN, opened.status());

        var reviewing = repository.transitionReviewCase(new ReviewTransition(
                caseId, 1, ReviewStatus.UNDER_REVIEW, "assigned to human reviewer", "", "review-portal"),
                audit("review-portal", "REVIEW_TRANSITIONED", "REVIEW_CASE", caseId));
        assertEquals(2, reviewing.version());

        Callable<Boolean> transition = () -> {
            try {
                repository.transitionReviewCase(new ReviewTransition(
                        caseId, 2, ReviewStatus.ACTION_RECOMMENDED,
                        "two independently sourced signals were corroborated",
                        "temporarily restrict ranked access pending appeal", "review-portal"),
                        audit("review-portal", "REVIEW_TRANSITIONED", "REVIEW_CASE", caseId));
                return true;
            } catch (WorkflowConflictException expectedConflict) {
                assertEquals(WorkflowConflictException.Kind.VERSION_MISMATCH, expectedConflict.kind());
                return false;
            }
        };
        List<Future<Boolean>> transitions = new ArrayList<>();
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            transitions.add(executor.submit(transition));
            transitions.add(executor.submit(transition));
            int successes = 0;
            for (Future<Boolean> future : transitions) if (future.get()) successes++;
            assertEquals(1, successes);
        }

        UUID wrongAppealId = UUID.randomUUID();
        assertThrows(WorkflowConflictException.class, () -> repository.createAppeal(
                new AppealDraft(wrongAppealId, caseId, UUID.randomUUID(),
                        "wrong player fixture", "appeal-portal"),
                audit("appeal-portal", "APPEAL_SUBMITTED", "APPEAL", wrongAppealId)));

        UUID appealId = UUID.randomUUID();
        var submitted = repository.createAppeal(
                new AppealDraft(appealId, caseId, playerId,
                        "Please consider a controlled desynchronization fixture.", "appeal-portal"),
                audit("appeal-portal", "APPEAL_SUBMITTED", "APPEAL", appealId));
        assertEquals(AppealStatus.SUBMITTED, submitted.status());
        var appealReview = repository.transitionAppeal(new AppealTransition(
                appealId, 1, AppealStatus.UNDER_REVIEW, "assigned to separate reviewer", "appeal-portal"),
                audit("appeal-portal", "APPEAL_TRANSITIONED", "APPEAL", appealId));
        assertEquals(2, appealReview.version());
        var granted = repository.transitionAppeal(new AppealTransition(
                appealId, 2, AppealStatus.GRANTED,
                "known-good replay reproduced the alert under packet loss", "appeal-portal"),
                audit("appeal-portal", "APPEAL_TRANSITIONED", "APPEAL", appealId));
        assertEquals(AppealStatus.GRANTED, granted.status());
        assertThrows(WorkflowConflictException.class, () -> repository.transitionAppeal(
                new AppealTransition(appealId, 3, AppealStatus.UNDER_REVIEW,
                        "terminal appeals cannot reopen", "appeal-portal"),
                audit("appeal-portal", "APPEAL_TRANSITIONED", "APPEAL", appealId)));

        var timeline = repository.findPlayerTimeline(playerId, 100);
        assertEquals(1, timeline.reviews().size());
        assertEquals(ReviewStatus.ACTION_RECOMMENDED, timeline.reviews().getFirst().status());
        assertEquals(1, timeline.appeals().size());
        assertEquals(AppealStatus.GRANTED, timeline.appeals().getFirst().status());
        assertEquals(6, timeline.workflowEvents().size());
        assertTrue(timeline.workflowEvents().stream()
                .anyMatch(value -> value.fromStatus().equals("UNDER_REVIEW")
                        && value.toStatus().equals("GRANTED")));
        assertEquals(3, scalarLong(
                "SELECT count(*) FROM mcace_review_transitions WHERE case_id = '" + caseId + "'"));
        assertEquals(3, scalarLong(
                "SELECT count(*) FROM mcace_appeal_transitions WHERE appeal_id = '" + appealId + "'"));

        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            assertThrows(SQLException.class, () -> statement.executeUpdate(
                    "UPDATE mcace_review_cases SET status = 'CLOSED_ACTIONED', version = version + 1 "
                            + "WHERE case_id = '" + caseId + "'"));
            assertThrows(SQLException.class, () -> statement.executeUpdate(
                    "UPDATE mcace_review_transitions SET actor_id = 'tampered' WHERE case_id = '" + caseId + "'"));
            assertThrows(SQLException.class, () -> statement.executeUpdate(
                    "DELETE FROM mcace_appeals WHERE appeal_id = '" + appealId + "'"));
        }
    }

    private static OperatorAuditRecord audit(
            String actor, String action, String targetType, UUID targetId) {
        return new OperatorAuditRecord(
                UUID.randomUUID(), actor, action, targetType, targetId.toString(), NOW,
                "{\"fixture\":true}");
    }

    private static RiskPolicyReleaseDraft policyRelease(UUID policyId, String version, int unknownModWeight) {
        java.util.EnumMap<RiskEventType, Integer> weights = new java.util.EnumMap<>(RiskEventType.class);
        for (RiskEventType type : RiskEventType.values()) {
            weights.put(type, RiskPolicy.defaults().weights().get(type));
        }
        weights.put(RiskEventType.UNKNOWN_MOD, unknownModWeight);
        return new RiskPolicyReleaseDraft(
                policyId, new RiskPolicy(version, weights, 20, 50, 80),
                "integration policy fixture", "policy-operator");
    }

    private static SessionAuditRecord session(UUID playerId) {
        return new SessionAuditRecord(
                "integration-session", playerId, "integration-network", "phase2-v3", 1,
                SessionStage.CHALLENGE_SENT, TrustLevel.UNKNOWN, AdmissionStatus.VERIFYING,
                0, RiskBand.NORMAL, "", "", LoaderType.LOADER_UNSPECIFIED,
                NOW, NOW, NOW.plusSeconds(30));
    }

    private static EvidenceMetadataDraft evidence(UUID playerId, int fixture) {
        byte[] hash = new byte[32];
        java.util.Arrays.fill(hash, (byte) (fixture + 1));
        return new EvidenceMetadataDraft(
                UUID.randomUUID(), playerId, "integration-session", EvidenceType.MOD_LIST,
                ObservationOrigin.CLIENT_REPORTED, NOW.plusSeconds(fixture), fixture + 10L, hash,
                "s3://mcace-integration/" + fixture, "integration-operator");
    }

    private static long scalarLong(String sql) throws SQLException {
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             var result = statement.executeQuery(sql)) {
            result.next();
            return result.getLong(1);
        }
    }
}
