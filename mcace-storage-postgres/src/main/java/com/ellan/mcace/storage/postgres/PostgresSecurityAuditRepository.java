package com.ellan.mcace.storage.postgres;

import com.ellan.mcace.core.persistence.EvidenceMetadataDraft;
import com.ellan.mcace.core.persistence.AuditAnchorPublication;
import com.ellan.mcace.core.persistence.AuditAnchorStore;
import com.ellan.mcace.core.persistence.CloudControlPlaneStore;
import com.ellan.mcace.core.persistence.AppealDraft;
import com.ellan.mcace.core.persistence.AppealStatus;
import com.ellan.mcace.core.persistence.AppealTransition;
import com.ellan.mcace.core.persistence.ObservationOrigin;
import com.ellan.mcace.core.persistence.OperatorAuditRecord;
import com.ellan.mcace.core.persistence.PlayerTimeline;
import com.ellan.mcace.core.persistence.PlayerNotification;
import com.ellan.mcace.core.persistence.PolicyMetrics;
import com.ellan.mcace.core.persistence.PolicyRolloutDraft;
import com.ellan.mcace.core.persistence.PolicyRolloutStage;
import com.ellan.mcace.core.persistence.RevocationDraft;
import com.ellan.mcace.core.persistence.RevocationSignatureCodec;
import com.ellan.mcace.core.persistence.RevocationSubjectType;
import com.ellan.mcace.core.persistence.RiskEventAuditRecord;
import com.ellan.mcace.core.persistence.RiskFeedbackDraft;
import com.ellan.mcace.core.persistence.RiskFeedbackLabel;
import com.ellan.mcace.core.persistence.RiskPolicyDeployment;
import com.ellan.mcace.core.persistence.RiskPolicyEvaluation;
import com.ellan.mcace.core.persistence.RiskPolicyReleaseCodec;
import com.ellan.mcace.core.persistence.RiskPolicyReleaseDraft;
import com.ellan.mcace.core.persistence.ReviewCaseDraft;
import com.ellan.mcace.core.persistence.ReviewStatus;
import com.ellan.mcace.core.persistence.ReviewTransition;
import com.ellan.mcace.core.persistence.SecurityAuditSink;
import com.ellan.mcace.core.persistence.SecurityPersistenceException;
import com.ellan.mcace.core.persistence.SessionAuditRecord;
import com.ellan.mcace.core.persistence.StoredEvidenceMetadata;
import com.ellan.mcace.core.persistence.StoredAuditAnchor;
import com.ellan.mcace.core.persistence.StoredAppeal;
import com.ellan.mcace.core.persistence.StoredReviewCase;
import com.ellan.mcace.core.persistence.StoredRevocation;
import com.ellan.mcace.core.persistence.StoredPolicyRollout;
import com.ellan.mcace.core.persistence.StoredRiskPolicyRelease;
import com.ellan.mcace.core.persistence.StoredWebSession;
import com.ellan.mcace.core.persistence.WebPortalStore;
import com.ellan.mcace.core.persistence.WebPrincipalType;
import com.ellan.mcace.core.persistence.WebRole;
import com.ellan.mcace.core.persistence.WebSessionHandoff;
import com.ellan.mcace.core.persistence.WorkflowConflictException;
import com.ellan.mcace.core.persistence.WorkflowTimelineEvent;
import com.ellan.mcace.core.risk.RiskEventType;
import com.ellan.mcace.core.risk.RiskPolicy;
import com.ellan.mcace.core.session.SessionStage;
import com.ellan.mcace.protocol.generated.EvidenceType;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.RiskBand;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.Comparator;
import javax.sql.DataSource;

public final class PostgresSecurityAuditRepository
        implements SecurityAuditSink, CloudControlPlaneStore, AuditAnchorStore, WebPortalStore {
    private static final byte[] EMPTY_CHAIN_HASH = new byte[32];

    private final DataSource dataSource;
    private final EvidenceChainSigner evidenceSigner;
    private final RevocationSigner revocationSigner;
    private final AuditAnchorSigner auditAnchorSigner;
    private final Clock clock;

    public PostgresSecurityAuditRepository(
            DataSource dataSource,
            EvidenceChainSigner evidenceSigner,
            Clock clock) {
        this(dataSource, evidenceSigner, new DisabledRevocationSigner(),
                new DisabledAuditAnchorSigner(), clock);
    }

    public PostgresSecurityAuditRepository(
            DataSource dataSource,
            EvidenceChainSigner evidenceSigner,
            RevocationSigner revocationSigner,
            Clock clock) {
        this(dataSource, evidenceSigner, revocationSigner, new DisabledAuditAnchorSigner(), clock);
    }

    public PostgresSecurityAuditRepository(
            DataSource dataSource,
            EvidenceChainSigner evidenceSigner,
            RevocationSigner revocationSigner,
            AuditAnchorSigner auditAnchorSigner,
            Clock clock) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
        this.evidenceSigner = Objects.requireNonNull(evidenceSigner, "evidenceSigner");
        this.revocationSigner = Objects.requireNonNull(revocationSigner, "revocationSigner");
        this.auditAnchorSigner = Objects.requireNonNull(auditAnchorSigner, "auditAnchorSigner");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public void upsertSession(SessionAuditRecord session) throws SecurityPersistenceException {
        Objects.requireNonNull(session, "session");
        String sql = """
                INSERT INTO mcace_sessions(
                    session_id, player_uuid, server_id, policy_version, policy_sequence,
                    stage, trust_level, admission_status, risk_score, risk_band,
                    client_build_id, minecraft_version, loader, started_at, updated_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (session_id) DO UPDATE SET
                    player_uuid = EXCLUDED.player_uuid,
                    server_id = EXCLUDED.server_id,
                    policy_version = EXCLUDED.policy_version,
                    policy_sequence = EXCLUDED.policy_sequence,
                    stage = EXCLUDED.stage,
                    trust_level = EXCLUDED.trust_level,
                    admission_status = EXCLUDED.admission_status,
                    risk_score = EXCLUDED.risk_score,
                    risk_band = EXCLUDED.risk_band,
                    client_build_id = EXCLUDED.client_build_id,
                    minecraft_version = EXCLUDED.minecraft_version,
                    loader = EXCLUDED.loader,
                    started_at = LEAST(mcace_sessions.started_at, EXCLUDED.started_at),
                    updated_at = EXCLUDED.updated_at,
                    expires_at = EXCLUDED.expires_at
                WHERE EXCLUDED.updated_at >= mcace_sessions.updated_at
                """;
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            bindSession(statement, session);
            statement.executeUpdate();
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot persist MCAce session", exception);
        }
    }

    @Override
    public void appendRiskEvent(RiskEventAuditRecord event) throws SecurityPersistenceException {
        Objects.requireNonNull(event, "event");
        try (Connection connection = dataSource.getConnection()) {
            insertRiskEvent(connection, event);
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot append MCAce risk event", exception);
        }
    }

    @Override
    public StoredEvidenceMetadata appendEvidence(EvidenceMetadataDraft evidence)
            throws SecurityPersistenceException {
        Objects.requireNonNull(evidence, "evidence");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                ChainHead head = lockHead(connection);
                long sequence = Math.addExact(head.sequence(), 1);
                Instant storedAt = clock.instant();
                byte[] chainHash = EvidenceChainCodec.hash(head.hash(), sequence, evidence, storedAt);
                byte[] signature = evidenceSigner.sign(chainHash);
                insertEvidence(connection, evidence, sequence, storedAt, head.hash(), chainHash, signature);
                try (PreparedStatement update = connection.prepareStatement("""
                        UPDATE mcace_evidence_chain_head
                        SET last_sequence = ?, last_hash = ?
                        WHERE singleton = TRUE
                        """)) {
                    update.setLong(1, sequence);
                    update.setBytes(2, chainHash);
                    if (update.executeUpdate() != 1) {
                        throw new SQLException("evidence chain head is missing");
                    }
                }
                connection.commit();
                return new StoredEvidenceMetadata(
                        evidence, sequence, storedAt, head.hash(), chainHash, signature, evidenceSigner.keyId());
            } catch (SQLException | ArithmeticException | SecurityPersistenceException exception) {
                rollback(connection, exception);
                if (exception instanceof SecurityPersistenceException persistenceException) {
                    throw persistenceException;
                }
                throw new SecurityPersistenceException("cannot append MCAce evidence metadata", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot connect to append MCAce evidence", exception);
        }
    }

    @Override
    public StoredRevocation appendRevocation(RevocationDraft revocation, OperatorAuditRecord audit)
            throws SecurityPersistenceException {
        Objects.requireNonNull(revocation, "revocation");
        Objects.requireNonNull(audit, "audit");
        if (!revocation.actorId().equals(audit.actorId())) {
            throw new IllegalArgumentException("revocation and audit actors differ");
        }
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                long sequence = nextRevocationSequence(connection);
                Instant createdAt = clock.instant();
                byte[] payloadHash = RevocationSignatureCodec.hash(sequence, revocation, createdAt);
                byte[] signature = revocationSigner.sign(payloadHash);
                insertRevocation(connection, revocation, sequence, createdAt, payloadHash, signature);
                insertOperatorAudit(connection, audit);
                connection.commit();
                return new StoredRevocation(
                        revocation, sequence, createdAt, payloadHash, signature, revocationSigner.keyId());
            } catch (SQLException | SecurityPersistenceException exception) {
                rollback(connection, exception);
                if (exception instanceof SecurityPersistenceException persistenceException) {
                    throw persistenceException;
                }
                throw new SecurityPersistenceException("cannot append MCAce revocation", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot connect to append MCAce revocation", exception);
        }
    }

    @Override
    public void checkHealth() throws SecurityPersistenceException {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("SELECT 1");
             ResultSet result = statement.executeQuery()) {
            if (!result.next() || result.getInt(1) != 1) throw new SQLException("unexpected health response");
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cloud control-plane storage health check failed", exception);
        }
    }

    @Override
    public Optional<StoredAuditAnchor> createAuditAnchor(Duration minimumInterval)
            throws SecurityPersistenceException {
        Objects.requireNonNull(minimumInterval, "minimumInterval");
        if (minimumInterval.isNegative() || minimumInterval.compareTo(Duration.ofDays(1)) > 0) {
            throw new IllegalArgumentException("minimumInterval must be between zero and one day");
        }
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                AuditAnchorHead previous = lockAuditAnchorHead(connection);
                Instant createdAt = clock.instant();
                if (previous.createdAt() != null
                        && createdAt.isBefore(previous.createdAt().plus(minimumInterval))) {
                    connection.commit();
                    return Optional.empty();
                }
                ChainHead evidence = readEvidenceHead(connection);
                DigestHead revocations = digestRevocations(connection);
                DigestHead operatorAudits = digestOperatorAudits(connection);
                long sequence = Math.addExact(previous.sequence(), 1L);
                UUID anchorId = UUID.randomUUID();
                byte[] anchorHash = AuditAnchorCodec.hash(
                        anchorId, sequence, createdAt, evidence.sequence(), evidence.hash(),
                        revocations.count(), revocations.maximumSequence(), revocations.hash(),
                        operatorAudits.count(), operatorAudits.hash(), previous.hash());
                byte[] signature = auditAnchorSigner.sign(anchorHash);
                StoredAuditAnchor anchor = new StoredAuditAnchor(
                        anchorId, sequence, createdAt, evidence.sequence(), evidence.hash(),
                        revocations.count(), revocations.maximumSequence(), revocations.hash(),
                        operatorAudits.count(), operatorAudits.hash(), previous.hash(), anchorHash,
                        signature, auditAnchorSigner.keyId());
                insertAuditAnchor(connection, anchor);
                insertAuditAnchorDelivery(connection, anchor);
                updateAuditAnchorHead(connection, anchor);
                connection.commit();
                return Optional.of(anchor);
            } catch (SQLException | ArithmeticException | SecurityPersistenceException exception) {
                rollback(connection, exception);
                if (exception instanceof SecurityPersistenceException persistenceException) {
                    throw persistenceException;
                }
                throw new SecurityPersistenceException("cannot create MCAce audit anchor", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot connect to create MCAce audit anchor", exception);
        }
    }

    @Override
    public List<StoredAuditAnchor> claimPendingAuditAnchors(
            String workerId, Duration leaseDuration, int limit) throws SecurityPersistenceException {
        workerId = requireWorkerId(workerId);
        Objects.requireNonNull(leaseDuration, "leaseDuration");
        if (leaseDuration.isZero() || leaseDuration.isNegative()
                || leaseDuration.compareTo(Duration.ofMinutes(10)) > 0) {
            throw new IllegalArgumentException("leaseDuration must be between 1 ms and 10 minutes");
        }
        if (limit < 1 || limit > 100) {
            throw new IllegalArgumentException("audit anchor claim limit must be between 1 and 100");
        }
        Instant now = clock.instant();
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                List<UUID> claimed = new ArrayList<>();
                try (PreparedStatement statement = connection.prepareStatement("""
                        WITH pending AS (
                            SELECT delivery.anchor_id
                            FROM mcace_audit_anchor_delivery delivery
                            JOIN mcace_audit_anchors anchor ON anchor.anchor_id = delivery.anchor_id
                            WHERE delivery.next_attempt_at <= ?
                              AND (delivery.lease_until IS NULL OR delivery.lease_until <= ?)
                            ORDER BY anchor.sequence
                            FOR UPDATE OF delivery SKIP LOCKED
                            LIMIT ?
                        )
                        UPDATE mcace_audit_anchor_delivery delivery
                        SET lease_owner = ?, lease_until = ?, attempt_count = attempt_count + 1
                        FROM pending
                        WHERE delivery.anchor_id = pending.anchor_id
                        RETURNING delivery.anchor_id
                        """)) {
                    statement.setTimestamp(1, Timestamp.from(now));
                    statement.setTimestamp(2, Timestamp.from(now));
                    statement.setInt(3, limit);
                    statement.setString(4, workerId);
                    statement.setTimestamp(5, Timestamp.from(now.plus(leaseDuration)));
                    try (ResultSet result = statement.executeQuery()) {
                        while (result.next()) {
                            claimed.add(result.getObject(1, UUID.class));
                        }
                    }
                }
                List<StoredAuditAnchor> anchors = new ArrayList<>();
                for (UUID anchorId : claimed) {
                    anchors.add(findAuditAnchor(connection, anchorId));
                }
                anchors.sort(Comparator.comparingLong(StoredAuditAnchor::sequence));
                connection.commit();
                return List.copyOf(anchors);
            } catch (SQLException exception) {
                rollback(connection, exception);
                throw new SecurityPersistenceException("cannot claim MCAce audit anchors", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot connect to claim MCAce audit anchors", exception);
        }
    }

    @Override
    public void recordAuditAnchorPublication(
            UUID anchorId, String workerId, AuditAnchorPublication publication)
            throws SecurityPersistenceException {
        Objects.requireNonNull(anchorId, "anchorId");
        workerId = requireWorkerId(workerId);
        Objects.requireNonNull(publication, "publication");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO mcace_audit_anchor_publications(
                            anchor_id, destination_uri, published_at, receipt_reference, receipt_sha256)
                        SELECT ?, ?, ?, ?, ?
                        WHERE EXISTS (
                            SELECT 1 FROM mcace_audit_anchor_delivery
                            WHERE anchor_id = ? AND lease_owner = ?)
                        """)) {
                    statement.setObject(1, anchorId);
                    statement.setString(2, publication.destination().toString());
                    statement.setTimestamp(3, Timestamp.from(publication.publishedAt()));
                    statement.setString(4, publication.receiptReference());
                    statement.setBytes(5, publication.receiptSha256());
                    statement.setObject(6, anchorId);
                    statement.setString(7, workerId);
                    if (statement.executeUpdate() != 1) {
                        throw new SQLException("audit anchor publication lease is not owned");
                    }
                }
                try (PreparedStatement statement = connection.prepareStatement("""
                        DELETE FROM mcace_audit_anchor_delivery
                        WHERE anchor_id = ? AND lease_owner = ?
                        """)) {
                    statement.setObject(1, anchorId);
                    statement.setString(2, workerId);
                    if (statement.executeUpdate() != 1) {
                        throw new SQLException("audit anchor delivery row is missing");
                    }
                }
                connection.commit();
            } catch (SQLException exception) {
                rollback(connection, exception);
                throw new SecurityPersistenceException("cannot record MCAce audit anchor publication", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException(
                    "cannot connect to record MCAce audit anchor publication", exception);
        }
    }

    @Override
    public void releaseAuditAnchorClaim(
            UUID anchorId, String workerId, Duration retryDelay, String failure)
            throws SecurityPersistenceException {
        Objects.requireNonNull(anchorId, "anchorId");
        workerId = requireWorkerId(workerId);
        Objects.requireNonNull(retryDelay, "retryDelay");
        if (retryDelay.isNegative() || retryDelay.compareTo(Duration.ofHours(1)) > 0) {
            throw new IllegalArgumentException("retryDelay must be between zero and one hour");
        }
        Objects.requireNonNull(failure, "failure");
        String boundedFailure = failure.strip();
        if (boundedFailure.length() > 512) {
            boundedFailure = boundedFailure.substring(0, 512);
        }
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     UPDATE mcace_audit_anchor_delivery
                     SET lease_owner = NULL, lease_until = NULL, next_attempt_at = ?, last_error = ?
                     WHERE anchor_id = ? AND lease_owner = ?
                     """)) {
            statement.setTimestamp(1, Timestamp.from(clock.instant().plus(retryDelay)));
            statement.setString(2, boundedFailure);
            statement.setObject(3, anchorId);
            statement.setString(4, workerId);
            if (statement.executeUpdate() != 1) {
                throw new SQLException("audit anchor release lease is not owned");
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot release MCAce audit anchor claim", exception);
        }
    }

    @Override
    public List<StoredRevocation> findRevocationsAfter(long sequence, Instant activeAt, int limit)
            throws SecurityPersistenceException {
        Objects.requireNonNull(activeAt, "activeAt");
        if (sequence < 0 || limit <= 0 || limit > 1_000) {
            throw new IllegalArgumentException("invalid revocation query bounds");
        }
        String sql = """
                SELECT sequence, revocation_id, subject_type, subject_id, reason_code,
                       effective_at, expires_at, actor_id, created_at, payload_sha256,
                       server_signature, signer_key_id
                FROM mcace_revocations
                WHERE sequence > ? AND effective_at <= ? AND (expires_at IS NULL OR expires_at > ?)
                ORDER BY sequence LIMIT ?
                """;
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setLong(1, sequence);
            statement.setTimestamp(2, Timestamp.from(activeAt));
            statement.setTimestamp(3, Timestamp.from(activeAt));
            statement.setInt(4, limit);
            try (ResultSet result = statement.executeQuery()) {
                List<StoredRevocation> revocations = new ArrayList<>();
                while (result.next()) revocations.add(readRevocation(result));
                return List.copyOf(revocations);
            }
        } catch (SQLException | IllegalArgumentException exception) {
            throw new SecurityPersistenceException("cannot query MCAce revocations", exception);
        }
    }

    @Override
    public void appendOperatorAudit(OperatorAuditRecord audit) throws SecurityPersistenceException {
        Objects.requireNonNull(audit, "audit");
        try (Connection connection = dataSource.getConnection()) {
            insertOperatorAudit(connection, audit);
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot append MCAce operator audit", exception);
        }
    }

    @Override
    public void createWebHandoff(WebSessionHandoff handoff) throws SecurityPersistenceException {
        Objects.requireNonNull(handoff, "handoff");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                purgeExpiredWebCredentials(connection, handoff.createdAt());
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO mcace_web_handoffs(
                            handoff_id, secret_sha256, principal_type, subject_id, roles,
                            redirect_path, created_by, created_at, expires_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """)) {
                    statement.setObject(1, handoff.handoffId());
                    statement.setBytes(2, handoff.secretSha256());
                    statement.setString(3, handoff.principalType().name());
                    statement.setString(4, handoff.subjectId());
                    statement.setArray(5, roleArray(connection, handoff.roles()));
                    statement.setString(6, handoff.redirectPath());
                    statement.setString(7, handoff.createdBy());
                    statement.setTimestamp(8, Timestamp.from(handoff.createdAt()));
                    statement.setTimestamp(9, Timestamp.from(handoff.expiresAt()));
                    statement.executeUpdate();
                }
                connection.commit();
            } catch (SQLException exception) {
                rollback(connection, exception);
                throw new SecurityPersistenceException("cannot create MCAce web handoff", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot connect to create MCAce web handoff", exception);
        }
    }

    @Override
    public Optional<WebSessionHandoff> consumeWebHandoff(UUID handoffId)
            throws SecurityPersistenceException {
        Objects.requireNonNull(handoffId, "handoffId");
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     DELETE FROM mcace_web_handoffs WHERE handoff_id = ?
                     RETURNING handoff_id, secret_sha256, principal_type, subject_id, roles,
                               redirect_path, created_by, created_at, expires_at
                     """)) {
            statement.setObject(1, handoffId);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? Optional.of(readWebHandoff(result)) : Optional.empty();
            }
        } catch (SQLException | IllegalArgumentException exception) {
            throw new SecurityPersistenceException("cannot consume MCAce web handoff", exception);
        }
    }

    @Override
    public void createWebSession(StoredWebSession session) throws SecurityPersistenceException {
        Objects.requireNonNull(session, "session");
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                purgeExpiredWebCredentials(connection, session.createdAt());
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO mcace_web_sessions(
                            session_id, secret_sha256, principal_type, subject_id, roles,
                            created_by, created_at, expires_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """)) {
                    statement.setObject(1, session.sessionId());
                    statement.setBytes(2, session.secretSha256());
                    statement.setString(3, session.principalType().name());
                    statement.setString(4, session.subjectId());
                    statement.setArray(5, roleArray(connection, session.roles()));
                    statement.setString(6, session.createdBy());
                    statement.setTimestamp(7, Timestamp.from(session.createdAt()));
                    statement.setTimestamp(8, Timestamp.from(session.expiresAt()));
                    statement.executeUpdate();
                }
                connection.commit();
            } catch (SQLException exception) {
                rollback(connection, exception);
                throw new SecurityPersistenceException("cannot create MCAce web session", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot connect to create MCAce web session", exception);
        }
    }

    @Override
    public Optional<StoredWebSession> findActiveWebSession(byte[] secretSha256, Instant activeAt)
            throws SecurityPersistenceException {
        requireSha256(secretSha256);
        Objects.requireNonNull(activeAt, "activeAt");
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT session_id, secret_sha256, principal_type, subject_id, roles,
                            created_by, created_at, expires_at
                     FROM mcace_web_sessions
                     WHERE secret_sha256 = ? AND expires_at > ?
                     """)) {
            statement.setBytes(1, secretSha256);
            statement.setTimestamp(2, Timestamp.from(activeAt));
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? Optional.of(readWebSession(result)) : Optional.empty();
            }
        } catch (SQLException | IllegalArgumentException exception) {
            throw new SecurityPersistenceException("cannot find MCAce web session", exception);
        }
    }

    @Override
    public void deleteWebSession(UUID sessionId, byte[] secretSha256)
            throws SecurityPersistenceException {
        Objects.requireNonNull(sessionId, "sessionId");
        requireSha256(secretSha256);
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "DELETE FROM mcace_web_sessions WHERE session_id = ? AND secret_sha256 = ?")) {
            statement.setObject(1, sessionId);
            statement.setBytes(2, secretSha256);
            statement.executeUpdate();
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot delete MCAce web session", exception);
        }
    }

    @Override
    public List<StoredReviewCase> findReviewQueue(int limit) throws SecurityPersistenceException {
        if (limit <= 0 || limit > 500) throw new IllegalArgumentException("invalid review queue limit");
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT case_id, player_uuid, title, reason, created_by, status,
                            recommendation, resolution, version, created_at, updated_at
                     FROM mcace_review_cases
                     ORDER BY
                         CASE WHEN status IN ('OPEN', 'UNDER_REVIEW', 'ACTION_RECOMMENDED')
                              THEN 0 ELSE 1 END,
                         updated_at DESC, case_id
                     LIMIT ?
                     """)) {
            statement.setInt(1, limit);
            try (ResultSet result = statement.executeQuery()) {
                List<StoredReviewCase> cases = new ArrayList<>();
                while (result.next()) cases.add(readReviewCase(result));
                return List.copyOf(cases);
            }
        } catch (SQLException | IllegalArgumentException exception) {
            throw new SecurityPersistenceException("cannot query MCAce review queue", exception);
        }
    }

    @Override
    public List<PlayerNotification> findPlayerNotifications(UUID playerId, int limit)
            throws SecurityPersistenceException {
        Objects.requireNonNull(playerId, "playerId");
        if (limit <= 0 || limit > 500) throw new IllegalArgumentException("invalid notification limit");
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT n.notification_id, n.player_uuid, n.type, n.subject_id,
                            n.title, n.message, n.created_by, n.created_at, r.read_at
                     FROM mcace_player_notifications n
                     LEFT JOIN mcace_player_notification_reads r
                       ON r.notification_id = n.notification_id
                      AND r.player_uuid = n.player_uuid
                     WHERE n.player_uuid = ?
                     ORDER BY n.created_at DESC, n.notification_id
                     LIMIT ?
                     """)) {
            statement.setObject(1, playerId);
            statement.setInt(2, limit);
            try (ResultSet result = statement.executeQuery()) {
                List<PlayerNotification> notifications = new ArrayList<>();
                while (result.next()) notifications.add(readPlayerNotification(result));
                return List.copyOf(notifications);
            }
        } catch (SQLException | IllegalArgumentException exception) {
            throw new SecurityPersistenceException("cannot query MCAce player notifications", exception);
        }
    }

    @Override
    public void markPlayerNotificationRead(UUID playerId, UUID notificationId, Instant readAt)
            throws SecurityPersistenceException {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(notificationId, "notificationId");
        Objects.requireNonNull(readAt, "readAt");
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     INSERT INTO mcace_player_notification_reads(notification_id, player_uuid, read_at)
                     SELECT notification_id, player_uuid, ?
                     FROM mcace_player_notifications
                     WHERE notification_id = ? AND player_uuid = ?
                     ON CONFLICT (notification_id) DO NOTHING
                     """)) {
            statement.setTimestamp(1, Timestamp.from(readAt));
            statement.setObject(2, notificationId);
            statement.setObject(3, playerId);
            statement.executeUpdate();
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot mark MCAce notification read", exception);
        }
    }

    @Override
    public StoredReviewCase createReviewCase(ReviewCaseDraft draft, OperatorAuditRecord audit)
            throws SecurityPersistenceException {
        Objects.requireNonNull(draft, "draft");
        requireWorkflowAudit(draft.createdBy(), audit, "REVIEW_CREATED", "REVIEW_CASE", draft.caseId());
        Instant now = clock.instant();
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO mcace_review_cases(
                            case_id, player_uuid, title, reason, created_by, status,
                            recommendation, resolution, version, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, 'OPEN', '', '', 1, ?, ?)
                        """)) {
                    statement.setObject(1, draft.caseId());
                    statement.setObject(2, draft.playerId());
                    statement.setString(3, draft.title());
                    statement.setString(4, draft.reason());
                    statement.setString(5, draft.createdBy());
                    statement.setTimestamp(6, Timestamp.from(now));
                    statement.setTimestamp(7, Timestamp.from(now));
                    statement.executeUpdate();
                }
                insertReviewTransition(connection, UUID.randomUUID(), draft.caseId(), null,
                        ReviewStatus.OPEN, 1, draft.createdBy(), draft.reason(), "", now);
                insertPlayerNotification(connection, draft.playerId(), "REVIEW_OPENED",
                        draft.caseId().toString(), "Review opened",
                        "A review case was opened and is awaiting assessment.", draft.createdBy(), now);
                insertOperatorAudit(connection, audit);
                connection.commit();
                return new StoredReviewCase(draft, ReviewStatus.OPEN, "", "", 1, now, now);
            } catch (SQLException exception) {
                rollback(connection, exception);
                throw new SecurityPersistenceException("cannot create MCAce review case", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot connect to create MCAce review case", exception);
        }
    }

    @Override
    public StoredReviewCase transitionReviewCase(ReviewTransition transition, OperatorAuditRecord audit)
            throws SecurityPersistenceException {
        Objects.requireNonNull(transition, "transition");
        requireWorkflowAudit(
                transition.actorId(), audit, "REVIEW_TRANSITIONED", "REVIEW_CASE", transition.caseId());
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                StoredReviewCase current = lockReviewCase(connection, transition.caseId());
                if (current.version() != transition.expectedVersion()) {
                    throw new WorkflowConflictException(WorkflowConflictException.Kind.VERSION_MISMATCH,
                            "review case version does not match");
                }
                if (!current.status().permits(transition.targetStatus())) {
                    throw new WorkflowConflictException(WorkflowConflictException.Kind.INVALID_TRANSITION,
                            "review case transition is not permitted");
                }
                long version = Math.addExact(current.version(), 1);
                Instant now = clock.instant();
                String recommendation = transition.targetStatus() == ReviewStatus.ACTION_RECOMMENDED
                        ? transition.recommendation() : current.recommendation();
                String resolution = switch (transition.targetStatus()) {
                    case CLOSED_ACTIONED, CLOSED_NO_ACTION -> transition.reason();
                    default -> current.resolution();
                };
                try (PreparedStatement statement = connection.prepareStatement("""
                        UPDATE mcace_review_cases
                        SET status = ?, recommendation = ?, resolution = ?, version = ?, updated_at = ?
                        WHERE case_id = ? AND version = ?
                        """)) {
                    statement.setString(1, transition.targetStatus().name());
                    statement.setString(2, recommendation);
                    statement.setString(3, resolution);
                    statement.setLong(4, version);
                    statement.setTimestamp(5, Timestamp.from(now));
                    statement.setObject(6, transition.caseId());
                    statement.setLong(7, transition.expectedVersion());
                    if (statement.executeUpdate() != 1) {
                        throw new WorkflowConflictException(WorkflowConflictException.Kind.VERSION_MISMATCH,
                                "review case was concurrently modified");
                    }
                }
                insertReviewTransition(connection, UUID.randomUUID(), transition.caseId(), current.status(),
                        transition.targetStatus(), version, transition.actorId(), transition.reason(),
                        transition.recommendation(), now);
                insertPlayerNotification(connection, current.draft().playerId(), "REVIEW_STATUS_CHANGED",
                        transition.caseId().toString(), "Review status updated",
                        "Your review case is now " + transition.targetStatus().name() + ".",
                        transition.actorId(), now);
                insertOperatorAudit(connection, audit);
                connection.commit();
                return new StoredReviewCase(current.draft(), transition.targetStatus(), recommendation,
                        resolution, version, current.createdAt(), now);
            } catch (SQLException | ArithmeticException | WorkflowConflictException exception) {
                rollback(connection, exception);
                if (exception instanceof WorkflowConflictException conflict) throw conflict;
                throw new SecurityPersistenceException("cannot transition MCAce review case", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot connect to transition MCAce review case", exception);
        }
    }

    @Override
    public StoredAppeal createAppeal(AppealDraft draft, OperatorAuditRecord audit)
            throws SecurityPersistenceException {
        Objects.requireNonNull(draft, "draft");
        requireWorkflowAudit(draft.submittedBy(), audit, "APPEAL_SUBMITTED", "APPEAL", draft.appealId());
        Instant now = clock.instant();
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                StoredReviewCase review = lockReviewCase(connection, draft.caseId());
                if (!review.draft().playerId().equals(draft.playerId())) {
                    throw new WorkflowConflictException(WorkflowConflictException.Kind.PLAYER_MISMATCH,
                            "appeal player does not match the review case");
                }
                if (review.status() != ReviewStatus.ACTION_RECOMMENDED
                        && review.status() != ReviewStatus.CLOSED_ACTIONED) {
                    throw new WorkflowConflictException(WorkflowConflictException.Kind.INVALID_TRANSITION,
                            "review case is not eligible for appeal");
                }
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO mcace_appeals(
                            appeal_id, case_id, player_uuid, statement, submitted_by, status,
                            decision_reason, version, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, 'SUBMITTED', '', 1, ?, ?)
                        """)) {
                    statement.setObject(1, draft.appealId());
                    statement.setObject(2, draft.caseId());
                    statement.setObject(3, draft.playerId());
                    statement.setString(4, draft.statement());
                    statement.setString(5, draft.submittedBy());
                    statement.setTimestamp(6, Timestamp.from(now));
                    statement.setTimestamp(7, Timestamp.from(now));
                    statement.executeUpdate();
                }
                insertAppealTransition(connection, UUID.randomUUID(), draft.appealId(), null,
                        AppealStatus.SUBMITTED, 1, draft.submittedBy(), draft.statement(), now);
                insertPlayerNotification(connection, draft.playerId(), "APPEAL_SUBMITTED",
                        draft.appealId().toString(), "Appeal submitted",
                        "Your appeal was received and is awaiting review.", draft.submittedBy(), now);
                insertOperatorAudit(connection, audit);
                connection.commit();
                return new StoredAppeal(draft, AppealStatus.SUBMITTED, "", 1, now, now);
            } catch (SQLException | WorkflowConflictException exception) {
                rollback(connection, exception);
                if (exception instanceof WorkflowConflictException conflict) throw conflict;
                throw new SecurityPersistenceException("cannot create MCAce appeal", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot connect to create MCAce appeal", exception);
        }
    }

    @Override
    public StoredAppeal transitionAppeal(AppealTransition transition, OperatorAuditRecord audit)
            throws SecurityPersistenceException {
        Objects.requireNonNull(transition, "transition");
        requireWorkflowAudit(
                transition.actorId(), audit, "APPEAL_TRANSITIONED", "APPEAL", transition.appealId());
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                StoredAppeal current = lockAppeal(connection, transition.appealId());
                if (current.version() != transition.expectedVersion()) {
                    throw new WorkflowConflictException(WorkflowConflictException.Kind.VERSION_MISMATCH,
                            "appeal version does not match");
                }
                if (!current.status().permits(transition.targetStatus())) {
                    throw new WorkflowConflictException(WorkflowConflictException.Kind.INVALID_TRANSITION,
                            "appeal transition is not permitted");
                }
                long version = Math.addExact(current.version(), 1);
                Instant now = clock.instant();
                String decision = switch (transition.targetStatus()) {
                    case GRANTED, UPHELD -> transition.reason();
                    default -> current.decisionReason();
                };
                try (PreparedStatement statement = connection.prepareStatement("""
                        UPDATE mcace_appeals
                        SET status = ?, decision_reason = ?, version = ?, updated_at = ?
                        WHERE appeal_id = ? AND version = ?
                        """)) {
                    statement.setString(1, transition.targetStatus().name());
                    statement.setString(2, decision);
                    statement.setLong(3, version);
                    statement.setTimestamp(4, Timestamp.from(now));
                    statement.setObject(5, transition.appealId());
                    statement.setLong(6, transition.expectedVersion());
                    if (statement.executeUpdate() != 1) {
                        throw new WorkflowConflictException(WorkflowConflictException.Kind.VERSION_MISMATCH,
                                "appeal was concurrently modified");
                    }
                }
                insertAppealTransition(connection, UUID.randomUUID(), transition.appealId(), current.status(),
                        transition.targetStatus(), version, transition.actorId(), transition.reason(), now);
                insertPlayerNotification(connection, current.draft().playerId(), "APPEAL_STATUS_CHANGED",
                        transition.appealId().toString(), "Appeal status updated",
                        "Your appeal is now " + transition.targetStatus().name() + ".",
                        transition.actorId(), now);
                insertOperatorAudit(connection, audit);
                connection.commit();
                return new StoredAppeal(current.draft(), transition.targetStatus(), decision, version,
                        current.createdAt(), now);
            } catch (SQLException | ArithmeticException | WorkflowConflictException exception) {
                rollback(connection, exception);
                if (exception instanceof WorkflowConflictException conflict) throw conflict;
                throw new SecurityPersistenceException("cannot transition MCAce appeal", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot connect to transition MCAce appeal", exception);
        }
    }

    @Override
    public PlayerTimeline findPlayerTimeline(UUID playerId, int limit) throws SecurityPersistenceException {
        Objects.requireNonNull(playerId, "playerId");
        if (limit <= 0 || limit > 500) throw new IllegalArgumentException("invalid timeline limit");
        try (Connection connection = dataSource.getConnection()) {
            return new PlayerTimeline(playerId,
                    findPlayerSessions(connection, playerId, limit),
                    findPlayerRiskEvents(connection, playerId, limit),
                    findPlayerPolicyEvaluations(connection, playerId, limit),
                    findPlayerEvidence(connection, playerId, limit),
                    findPlayerReviews(connection, playerId, limit),
                    findPlayerAppeals(connection, playerId, limit),
                    findWorkflowEvents(connection, playerId, limit));
        } catch (SQLException | IllegalArgumentException exception) {
            throw new SecurityPersistenceException("cannot query MCAce player timeline", exception);
        }
    }

    @Override
    public StoredRiskPolicyRelease createRiskPolicyRelease(
            RiskPolicyReleaseDraft draft, OperatorAuditRecord audit) throws SecurityPersistenceException {
        Objects.requireNonNull(draft, "draft");
        requireWorkflowAudit(
                draft.createdBy(), audit, "RISK_POLICY_CREATED", "RISK_POLICY", draft.policyId());
        byte[] digest = RiskPolicyReleaseCodec.hash(draft);
        Instant now = clock.instant();
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO mcace_risk_policy_releases(
                            policy_id, version, watch_threshold, restricted_threshold,
                            investigation_threshold, description, created_by, created_at, release_sha256)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """)) {
                    statement.setObject(1, draft.policyId());
                    statement.setString(2, draft.policy().version());
                    statement.setInt(3, draft.policy().watchThreshold());
                    statement.setInt(4, draft.policy().restrictedThreshold());
                    statement.setInt(5, draft.policy().investigationThreshold());
                    statement.setString(6, draft.description());
                    statement.setString(7, draft.createdBy());
                    statement.setTimestamp(8, Timestamp.from(now));
                    statement.setBytes(9, digest);
                    statement.executeUpdate();
                }
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO mcace_risk_policy_weights(policy_id, event_type, weight)
                        VALUES (?, ?, ?)
                        """)) {
                    for (RiskEventType type : RiskEventType.values()) {
                        statement.setObject(1, draft.policyId());
                        statement.setString(2, type.name());
                        statement.setInt(3, draft.policy().weights().get(type));
                        statement.addBatch();
                    }
                    statement.executeBatch();
                }
                insertOperatorAudit(connection, audit);
                connection.commit();
                return new StoredRiskPolicyRelease(draft, now, digest);
            } catch (SQLException exception) {
                rollback(connection, exception);
                throw new SecurityPersistenceException("cannot create MCAce risk policy release", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot connect to create MCAce risk policy release", exception);
        }
    }

    @Override
    public StoredPolicyRollout appendPolicyRollout(
            PolicyRolloutDraft draft, OperatorAuditRecord audit) throws SecurityPersistenceException {
        Objects.requireNonNull(draft, "draft");
        requireWorkflowAudit(
                draft.createdBy(), audit, "POLICY_ROLLOUT_APPENDED", "POLICY_ROLLOUT", draft.rolloutId());
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement lock = connection.prepareStatement(
                        "SELECT pg_advisory_xact_lock(5567361424287171)")) {
                    lock.execute();
                }
                StoredRiskPolicyRelease release = findRiskPolicyRelease(connection, draft.policyId());
                if (release == null) {
                    throw new WorkflowConflictException(
                            WorkflowConflictException.Kind.NOT_FOUND, "risk policy release does not exist");
                }
                StoredPolicyRollout current = findLatestPolicyRollout(connection, draft.policyId());
                StoredPolicyRollout global = findLatestPolicyRollout(connection, null);
                validateRolloutTransition(current, global, draft);
                long sequence = nextPolicyRolloutSequence(connection);
                Instant now = clock.instant();
                insertPolicyRollout(connection, sequence, draft, now);
                insertOperatorAudit(connection, audit);
                connection.commit();
                return new StoredPolicyRollout(sequence, draft, now);
            } catch (SQLException | WorkflowConflictException exception) {
                rollback(connection, exception);
                if (exception instanceof WorkflowConflictException conflict) throw conflict;
                throw new SecurityPersistenceException("cannot append MCAce policy rollout", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot connect to append MCAce policy rollout", exception);
        }
    }

    @Override
    public List<StoredRiskPolicyRelease> findRiskPolicyReleases(int limit)
            throws SecurityPersistenceException {
        if (limit <= 0 || limit > 500) throw new IllegalArgumentException("invalid policy release limit");
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT policy_id FROM mcace_risk_policy_releases
                     ORDER BY created_at DESC, policy_id LIMIT ?
                     """)) {
            statement.setInt(1, limit);
            try (ResultSet result = statement.executeQuery()) {
                List<StoredRiskPolicyRelease> releases = new ArrayList<>();
                while (result.next()) {
                    releases.add(Objects.requireNonNull(
                            findRiskPolicyRelease(connection, result.getObject(1, UUID.class))));
                }
                return List.copyOf(releases);
            }
        } catch (SQLException | IllegalArgumentException exception) {
            throw new SecurityPersistenceException("cannot query MCAce risk policy releases", exception);
        }
    }

    @Override
    public List<StoredPolicyRollout> findPolicyRolloutsAfter(long sequence, int limit)
            throws SecurityPersistenceException {
        if (sequence < 0 || limit <= 0 || limit > 1_000) {
            throw new IllegalArgumentException("invalid rollout query bounds");
        }
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT sequence, rollout_id, policy_id, stage, percentage,
                            reason, created_by, created_at
                     FROM mcace_policy_rollouts WHERE sequence > ? ORDER BY sequence LIMIT ?
                     """)) {
            statement.setLong(1, sequence);
            statement.setInt(2, limit);
            try (ResultSet result = statement.executeQuery()) {
                List<StoredPolicyRollout> rollouts = new ArrayList<>();
                while (result.next()) rollouts.add(readPolicyRollout(result));
                return List.copyOf(rollouts);
            }
        } catch (SQLException | IllegalArgumentException exception) {
            throw new SecurityPersistenceException("cannot query MCAce policy rollouts", exception);
        }
    }

    @Override
    public RiskPolicyDeployment findRiskPolicyDeployment() throws SecurityPersistenceException {
        try (Connection connection = dataSource.getConnection()) {
            connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
            connection.setAutoCommit(false);
            StoredPolicyRollout latest = findLatestPolicyRollout(connection, null);
            if (latest == null) {
                connection.commit();
                return RiskPolicyDeployment.builtin();
            }
            StoredRiskPolicyRelease full = findLatestFullPolicyRelease(connection);
            RiskPolicy baseline = full == null ? RiskPolicy.defaults() : full.draft().policy();
            if (latest.draft().stage() == PolicyRolloutStage.SHADOW
                    || latest.draft().stage() == PolicyRolloutStage.CANARY
                    || latest.draft().stage() == PolicyRolloutStage.BROAD) {
                StoredRiskPolicyRelease candidate = findRiskPolicyRelease(
                        connection, latest.draft().policyId());
                if (candidate == null) throw new SQLException("rollout references a missing policy release");
                RiskPolicyDeployment deployment = new RiskPolicyDeployment(
                        baseline, candidate.draft().policy(), candidate.draft().policyId(),
                        latest.draft().rolloutId(),
                        latest.draft().stage(), latest.draft().percentage());
                connection.commit();
                return deployment;
            }
            RiskPolicyDeployment deployment = new RiskPolicyDeployment(
                    baseline, null, null, null, latest.draft().stage(), latest.draft().percentage());
            connection.commit();
            return deployment;
        } catch (SQLException | IllegalArgumentException exception) {
            throw new SecurityPersistenceException("cannot resolve MCAce risk policy deployment", exception);
        }
    }

    @Override
    public void appendCloudRiskEvent(RiskEventAuditRecord event, RiskPolicyEvaluation evaluation)
            throws SecurityPersistenceException {
        Objects.requireNonNull(event, "event");
        Objects.requireNonNull(evaluation, "evaluation");
        if (!event.eventId().equals(evaluation.eventId()) || event.weight() != evaluation.assignedWeight()) {
            throw new IllegalArgumentException("risk event and policy evaluation differ");
        }
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                insertRiskEvent(connection, event);
                insertRiskPolicyEvaluation(connection, evaluation);
                connection.commit();
            } catch (SQLException exception) {
                rollback(connection, exception);
                throw new SecurityPersistenceException("cannot append cloud risk event and evaluation", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot connect to append cloud risk event", exception);
        }
    }

    @Override
    public void appendRiskFeedback(RiskFeedbackDraft feedback, OperatorAuditRecord audit)
            throws SecurityPersistenceException {
        Objects.requireNonNull(feedback, "feedback");
        requireWorkflowAudit(
                feedback.actorId(), audit, "RISK_FEEDBACK_RECORDED", "RISK_FEEDBACK", feedback.feedbackId());
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                try (PreparedStatement validate = connection.prepareStatement("""
                        SELECT re.player_uuid, rc.player_uuid, rc.status, COALESCE(a.status, '')
                        FROM mcace_risk_events re CROSS JOIN mcace_review_cases rc
                        LEFT JOIN mcace_appeals a ON a.case_id = rc.case_id
                        WHERE re.event_id = ? AND rc.case_id = ?
                        """)) {
                    validate.setObject(1, feedback.eventId());
                    validate.setObject(2, feedback.reviewCaseId());
                    try (ResultSet result = validate.executeQuery()) {
                        if (!result.next()) throw new WorkflowConflictException(
                                WorkflowConflictException.Kind.NOT_FOUND,
                                "risk event or review case does not exist");
                        if (!result.getObject(1, UUID.class).equals(result.getObject(2, UUID.class))) {
                            throw new WorkflowConflictException(
                                    WorkflowConflictException.Kind.PLAYER_MISMATCH,
                                    "risk event and review case belong to different players");
                        }
                        String reviewStatus = result.getString(3);
                        String appealStatus = result.getString(4);
                        if (feedback.label() == RiskFeedbackLabel.FALSE_POSITIVE
                                && !"CLOSED_NO_ACTION".equals(reviewStatus)
                                && !"GRANTED".equals(appealStatus)) {
                            throw new WorkflowConflictException(
                                    WorkflowConflictException.Kind.INVALID_TRANSITION,
                                    "false-positive feedback requires no-action closure or granted appeal");
                        }
                        if (feedback.label() == RiskFeedbackLabel.CONFIRMED_SIGNAL
                                && !"ACTION_RECOMMENDED".equals(reviewStatus)
                                && !"CLOSED_ACTIONED".equals(reviewStatus)
                                && !"UPHELD".equals(appealStatus)) {
                            throw new WorkflowConflictException(
                                    WorkflowConflictException.Kind.INVALID_TRANSITION,
                                    "confirmed feedback requires a corroborated review outcome");
                        }
                    }
                }
                try (PreparedStatement statement = connection.prepareStatement("""
                        INSERT INTO mcace_risk_feedback(
                            feedback_id, event_id, review_case_id, label, notes, actor_id, occurred_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """)) {
                    statement.setObject(1, feedback.feedbackId());
                    statement.setObject(2, feedback.eventId());
                    statement.setObject(3, feedback.reviewCaseId());
                    statement.setString(4, feedback.label().name());
                    statement.setString(5, feedback.notes());
                    statement.setString(6, feedback.actorId());
                    statement.setTimestamp(7, Timestamp.from(feedback.occurredAt()));
                    statement.executeUpdate();
                }
                insertOperatorAudit(connection, audit);
                connection.commit();
            } catch (SQLException | WorkflowConflictException exception) {
                rollback(connection, exception);
                if (exception instanceof WorkflowConflictException conflict) throw conflict;
                throw new SecurityPersistenceException("cannot append MCAce risk feedback", exception);
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot connect to append MCAce risk feedback", exception);
        }
    }

    @Override
    public PolicyMetrics policyMetrics(String policyVersion, Instant from, Instant to)
            throws SecurityPersistenceException {
        Objects.requireNonNull(policyVersion, "policyVersion");
        Objects.requireNonNull(from, "from");
        Objects.requireNonNull(to, "to");
        if (policyVersion.isBlank() || !to.isAfter(from) || java.time.Duration.between(from, to).toDays() > 366) {
            throw new IllegalArgumentException("invalid policy metrics query");
        }
        String sql = """
                WITH relevant AS (
                    SELECT e.event_id, e.applied_policy_version, e.candidate_policy_version,
                           e.stage, r.corroborated
                    FROM mcace_risk_policy_evaluations e
                    JOIN mcace_risk_events r ON r.event_id = e.event_id
                    WHERE e.evaluated_at >= ? AND e.evaluated_at < ?
                      AND (e.applied_policy_version = ? OR e.candidate_policy_version = ?)
                ), latest_feedback AS (
                    SELECT DISTINCT ON (f.event_id) f.event_id, f.label
                    FROM mcace_risk_feedback f JOIN relevant r ON r.event_id = f.event_id
                    ORDER BY f.event_id, f.occurred_at DESC, f.feedback_id DESC
                )
                SELECT count(*) AS evaluated,
                       count(*) FILTER (WHERE applied_policy_version = ?) AS applied,
                       count(*) FILTER (WHERE candidate_policy_version = ? AND stage = 'SHADOW') AS shadow,
                       count(*) FILTER (WHERE corroborated) AS corroborated,
                       (SELECT count(*) FROM latest_feedback) AS labeled,
                       (SELECT count(*) FROM latest_feedback WHERE label = 'CONFIRMED_SIGNAL') AS confirmed,
                       (SELECT count(*) FROM latest_feedback WHERE label = 'FALSE_POSITIVE') AS false_positive,
                       (SELECT count(*) FROM latest_feedback WHERE label = 'INCONCLUSIVE') AS inconclusive
                FROM relevant
                """;
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setTimestamp(1, Timestamp.from(from));
            statement.setTimestamp(2, Timestamp.from(to));
            for (int index = 3; index <= 6; index++) statement.setString(index, policyVersion);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) throw new SQLException("policy metrics query returned no row");
                return new PolicyMetrics(
                        policyVersion, from, to, result.getLong(1), result.getLong(2),
                        result.getLong(3), result.getLong(4), result.getLong(5),
                        result.getLong(6), result.getLong(7), result.getLong(8));
            }
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot query MCAce policy metrics", exception);
        }
    }

    public Optional<SessionAuditRecord> findSession(String sessionId) throws SecurityPersistenceException {
        String sql = """
                SELECT session_id, player_uuid, server_id, policy_version, policy_sequence,
                       stage, trust_level, admission_status, risk_score, risk_band,
                       client_build_id, minecraft_version, loader, started_at, updated_at, expires_at
                FROM mcace_sessions WHERE session_id = ?
                """;
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, sessionId);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? Optional.of(readSession(result)) : Optional.empty();
            }
        } catch (SQLException | IllegalArgumentException exception) {
            throw new SecurityPersistenceException("cannot query MCAce session", exception);
        }
    }

    public List<RiskEventAuditRecord> findRiskEvents(UUID playerId) throws SecurityPersistenceException {
        String sql = """
                SELECT event_id, COALESCE(session_id, ''), player_uuid, event_type, weight,
                       source, origin, corroborated, observed_at, details::text
                FROM mcace_risk_events WHERE player_uuid = ? ORDER BY observed_at, event_id
                """;
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, playerId);
            try (ResultSet result = statement.executeQuery()) {
                List<RiskEventAuditRecord> events = new ArrayList<>();
                while (result.next()) events.add(readRiskEvent(result));
                return List.copyOf(events);
            }
        } catch (SQLException | IllegalArgumentException exception) {
            throw new SecurityPersistenceException("cannot query MCAce risk events", exception);
        }
    }

    public List<StoredEvidenceMetadata> findEvidence() throws SecurityPersistenceException {
        String sql = """
                SELECT chain_sequence, evidence_id, player_uuid, COALESCE(session_id, ''),
                       evidence_type, origin, captured_at, stored_at, content_size, content_sha256,
                       storage_uri, operator_id, previous_chain_sha256, chain_sha256,
                       server_signature, signer_key_id
                FROM mcace_evidence_metadata ORDER BY chain_sequence
                """;
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(sql);
             ResultSet result = statement.executeQuery()) {
            List<StoredEvidenceMetadata> evidence = new ArrayList<>();
            while (result.next()) evidence.add(readEvidence(result));
            return List.copyOf(evidence);
        } catch (SQLException | IllegalArgumentException exception) {
            throw new SecurityPersistenceException("cannot query MCAce evidence metadata", exception);
        }
    }

    public EvidenceChainVerification verifyEvidenceChain(Map<String, PublicKey> trustedSigners)
            throws SecurityPersistenceException {
        Objects.requireNonNull(trustedSigners, "trustedSigners");
        List<StoredEvidenceMetadata> entries = findEvidence();
        byte[] expectedPrevious = EMPTY_CHAIN_HASH.clone();
        long expectedSequence = 1;
        for (StoredEvidenceMetadata stored : entries) {
            if (stored.chainSequence() != expectedSequence
                    || !MessageDigest.isEqual(expectedPrevious, stored.previousChainSha256())) {
                return EvidenceChainVerification.invalid(expectedSequence - 1, stored.chainSequence(),
                        "sequence or predecessor mismatch");
            }
            byte[] calculated = EvidenceChainCodec.hash(
                    expectedPrevious, expectedSequence, stored.evidence(), stored.storedAt());
            if (!MessageDigest.isEqual(calculated, stored.chainSha256())) {
                return EvidenceChainVerification.invalid(expectedSequence - 1, expectedSequence,
                        "chain hash mismatch");
            }
            PublicKey signer = trustedSigners.get(stored.signerKeyId());
            if (signer == null || !Ed25519EvidenceChainSigner.verify(
                    calculated, stored.serverSignature(), signer)) {
                return EvidenceChainVerification.invalid(expectedSequence - 1, expectedSequence,
                        "untrusted or invalid server signature");
            }
            expectedPrevious = calculated;
            expectedSequence++;
        }
        ChainHead head = readHead();
        if (head.sequence() != entries.size() || !MessageDigest.isEqual(expectedPrevious, head.hash())) {
            return EvidenceChainVerification.invalid(entries.size(), head.sequence(), "chain head mismatch");
        }
        return EvidenceChainVerification.valid(entries.size());
    }

    private ChainHead readHead() throws SecurityPersistenceException {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT last_sequence, last_hash FROM mcace_evidence_chain_head WHERE singleton = TRUE");
             ResultSet result = statement.executeQuery()) {
            if (!result.next()) throw new SQLException("evidence chain head is missing");
            return new ChainHead(result.getLong(1), result.getBytes(2));
        } catch (SQLException exception) {
            throw new SecurityPersistenceException("cannot read evidence chain head", exception);
        }
    }

    private static ChainHead readEvidenceHead(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT last_sequence, last_hash FROM mcace_evidence_chain_head WHERE singleton = TRUE");
             ResultSet result = statement.executeQuery()) {
            if (!result.next()) {
                throw new SQLException("evidence chain head is missing");
            }
            byte[] hash = result.getBytes(2);
            if (hash.length != 32) {
                throw new SQLException("invalid evidence chain head hash");
            }
            return new ChainHead(result.getLong(1), hash);
        }
    }

    private static AuditAnchorHead lockAuditAnchorHead(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT last_sequence, last_hash, last_created_at
                FROM mcace_audit_anchor_head WHERE singleton = TRUE FOR UPDATE
                """); ResultSet result = statement.executeQuery()) {
            if (!result.next()) {
                throw new SQLException("audit anchor head is missing");
            }
            byte[] hash = result.getBytes(2);
            if (hash.length != 32) {
                throw new SQLException("invalid audit anchor head hash");
            }
            Timestamp createdAt = result.getTimestamp(3);
            return new AuditAnchorHead(
                    result.getLong(1), hash, createdAt == null ? null : createdAt.toInstant());
        }
    }

    private static DigestHead digestRevocations(Connection connection)
            throws SQLException, SecurityPersistenceException {
        MessageDigest digest = AuditAnchorCodec.revocationDigest();
        long count = 0;
        long maximum = 0;
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT sequence, payload_sha256 FROM mcace_revocations ORDER BY sequence
                """); ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                long sequence = result.getLong(1);
                byte[] payloadHash = result.getBytes(2);
                if (payloadHash.length != 32 || sequence <= maximum) {
                    throw new SQLException("invalid ordered revocation feed");
                }
                AuditAnchorCodec.updateLong(digest, sequence);
                AuditAnchorCodec.updateBytes(digest, payloadHash);
                maximum = sequence;
                count++;
            }
        }
        return new DigestHead(count, maximum, digest.digest());
    }

    private static DigestHead digestOperatorAudits(Connection connection)
            throws SQLException, SecurityPersistenceException {
        MessageDigest digest = AuditAnchorCodec.operatorAuditDigest();
        long count = 0;
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT audit_id, actor_id, action, target_type, target_id,
                       occurred_at, details::text, inserted_at
                FROM mcace_operator_audit ORDER BY inserted_at, audit_id
                """); ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                UUID auditId = result.getObject(1, UUID.class);
                AuditAnchorCodec.updateLong(digest, auditId.getMostSignificantBits());
                AuditAnchorCodec.updateLong(digest, auditId.getLeastSignificantBits());
                AuditAnchorCodec.updateText(digest, result.getString(2));
                AuditAnchorCodec.updateText(digest, result.getString(3));
                AuditAnchorCodec.updateText(digest, result.getString(4));
                AuditAnchorCodec.updateText(digest, result.getString(5));
                updateInstant(digest, result.getTimestamp(6).toInstant());
                AuditAnchorCodec.updateText(digest, result.getString(7));
                updateInstant(digest, result.getTimestamp(8).toInstant());
                count++;
            }
        }
        return new DigestHead(count, count, digest.digest());
    }

    private static void updateInstant(MessageDigest digest, Instant value) {
        AuditAnchorCodec.updateLong(digest, value.getEpochSecond());
        AuditAnchorCodec.updateLong(digest, value.getNano());
    }

    private static void insertAuditAnchor(Connection connection, StoredAuditAnchor anchor) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO mcace_audit_anchors(
                    sequence, anchor_id, created_at, evidence_sequence, evidence_chain_sha256,
                    revocation_count, revocation_max_sequence, revocation_feed_sha256,
                    operator_audit_count, operator_audit_sha256, previous_anchor_sha256,
                    anchor_sha256, server_signature, signer_key_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setLong(1, anchor.sequence());
            statement.setObject(2, anchor.anchorId());
            statement.setTimestamp(3, Timestamp.from(anchor.createdAt()));
            statement.setLong(4, anchor.evidenceSequence());
            statement.setBytes(5, anchor.evidenceChainSha256());
            statement.setLong(6, anchor.revocationCount());
            statement.setLong(7, anchor.revocationMaxSequence());
            statement.setBytes(8, anchor.revocationFeedSha256());
            statement.setLong(9, anchor.operatorAuditCount());
            statement.setBytes(10, anchor.operatorAuditSha256());
            statement.setBytes(11, anchor.previousAnchorSha256());
            statement.setBytes(12, anchor.anchorSha256());
            statement.setBytes(13, anchor.serverSignature());
            statement.setString(14, anchor.signerKeyId());
            statement.executeUpdate();
        }
    }

    private static void insertAuditAnchorDelivery(Connection connection, StoredAuditAnchor anchor)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO mcace_audit_anchor_delivery(
                    anchor_id, lease_owner, lease_until, next_attempt_at, attempt_count, last_error)
                VALUES (?, NULL, NULL, ?, 0, '')
                """)) {
            statement.setObject(1, anchor.anchorId());
            statement.setTimestamp(2, Timestamp.from(anchor.createdAt()));
            statement.executeUpdate();
        }
    }

    private static void updateAuditAnchorHead(Connection connection, StoredAuditAnchor anchor)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE mcace_audit_anchor_head
                SET last_sequence = ?, last_hash = ?, last_created_at = ?
                WHERE singleton = TRUE
                """)) {
            statement.setLong(1, anchor.sequence());
            statement.setBytes(2, anchor.anchorSha256());
            statement.setTimestamp(3, Timestamp.from(anchor.createdAt()));
            if (statement.executeUpdate() != 1) {
                throw new SQLException("audit anchor head is missing");
            }
        }
    }

    private static StoredAuditAnchor findAuditAnchor(Connection connection, UUID anchorId)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT sequence, anchor_id, created_at, evidence_sequence, evidence_chain_sha256,
                       revocation_count, revocation_max_sequence, revocation_feed_sha256,
                       operator_audit_count, operator_audit_sha256, previous_anchor_sha256,
                       anchor_sha256, server_signature, signer_key_id
                FROM mcace_audit_anchors WHERE anchor_id = ?
                """)) {
            statement.setObject(1, anchorId);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new SQLException("audit anchor is missing");
                }
                return readAuditAnchor(result);
            }
        }
    }

    private static StoredAuditAnchor readAuditAnchor(ResultSet result) throws SQLException {
        return new StoredAuditAnchor(
                result.getObject(2, UUID.class), result.getLong(1), result.getTimestamp(3).toInstant(),
                result.getLong(4), result.getBytes(5), result.getLong(6), result.getLong(7),
                result.getBytes(8), result.getLong(9), result.getBytes(10), result.getBytes(11),
                result.getBytes(12), result.getBytes(13), result.getString(14));
    }

    private static String requireWorkerId(String workerId) {
        Objects.requireNonNull(workerId, "workerId");
        if (!workerId.matches("[A-Za-z0-9._:-]{1,128}")) {
            throw new IllegalArgumentException("invalid audit anchor worker identity");
        }
        return workerId;
    }

    private static ChainHead lockHead(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT last_sequence, last_hash FROM mcace_evidence_chain_head WHERE singleton = TRUE FOR UPDATE");
             ResultSet result = statement.executeQuery()) {
            if (!result.next()) throw new SQLException("evidence chain head is missing");
            byte[] hash = result.getBytes(2);
            if (hash.length != 32) throw new SQLException("invalid evidence chain head hash");
            return new ChainHead(result.getLong(1), hash);
        }
    }

    private void insertEvidence(
            Connection connection,
            EvidenceMetadataDraft evidence,
            long sequence,
            Instant storedAt,
            byte[] previous,
            byte[] chainHash,
            byte[] signature) throws SQLException {
        String sql = """
                INSERT INTO mcace_evidence_metadata(
                    chain_sequence, evidence_id, player_uuid, session_id, evidence_type, origin,
                    captured_at, stored_at, content_size, content_sha256, storage_uri, operator_id,
                    previous_chain_sha256, chain_sha256, server_signature, signer_key_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setLong(1, sequence);
            statement.setObject(2, evidence.evidenceId());
            statement.setObject(3, evidence.playerId());
            setNullableSession(statement, 4, evidence.sessionId());
            statement.setString(5, evidence.type().name());
            statement.setString(6, evidence.origin().name());
            statement.setTimestamp(7, Timestamp.from(evidence.capturedAt()));
            statement.setTimestamp(8, Timestamp.from(storedAt));
            statement.setLong(9, evidence.contentSize());
            statement.setBytes(10, evidence.contentSha256());
            statement.setString(11, evidence.storageUri());
            statement.setString(12, evidence.operatorId());
            statement.setBytes(13, previous);
            statement.setBytes(14, chainHash);
            statement.setBytes(15, signature);
            statement.setString(16, evidenceSigner.keyId());
            statement.executeUpdate();
        }
    }

    private static long nextRevocationSequence(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT nextval('mcace_revocation_sequence')");
             ResultSet result = statement.executeQuery()) {
            if (!result.next()) throw new SQLException("revocation sequence is unavailable");
            return result.getLong(1);
        }
    }

    private void insertRevocation(
            Connection connection,
            RevocationDraft revocation,
            long sequence,
            Instant createdAt,
            byte[] payloadHash,
            byte[] signature) throws SQLException {
        String sql = """
                INSERT INTO mcace_revocations(
                    sequence, revocation_id, subject_type, subject_id, reason_code,
                    effective_at, expires_at, actor_id, created_at, payload_sha256,
                    server_signature, signer_key_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setLong(1, sequence);
            statement.setObject(2, revocation.revocationId());
            statement.setString(3, revocation.subjectType().name());
            statement.setString(4, revocation.subjectId());
            statement.setString(5, revocation.reasonCode());
            statement.setTimestamp(6, Timestamp.from(revocation.effectiveAt()));
            if (revocation.expiresAt() == null) statement.setNull(7, Types.TIMESTAMP_WITH_TIMEZONE);
            else statement.setTimestamp(7, Timestamp.from(revocation.expiresAt()));
            statement.setString(8, revocation.actorId());
            statement.setTimestamp(9, Timestamp.from(createdAt));
            statement.setBytes(10, payloadHash);
            statement.setBytes(11, signature);
            statement.setString(12, revocationSigner.keyId());
            statement.executeUpdate();
        }
    }

    private static void insertOperatorAudit(Connection connection, OperatorAuditRecord audit) throws SQLException {
        String sql = """
                INSERT INTO mcace_operator_audit(
                    audit_id, actor_id, action, target_type, target_id, occurred_at, details)
                VALUES (?, ?, ?, ?, ?, ?, ?::jsonb)
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setObject(1, audit.auditId());
            statement.setString(2, audit.actorId());
            statement.setString(3, audit.action());
            statement.setString(4, audit.targetType());
            statement.setString(5, audit.targetId());
            statement.setTimestamp(6, Timestamp.from(audit.occurredAt()));
            statement.setString(7, audit.detailsJson());
            statement.executeUpdate();
        }
    }

    private static void insertRiskEvent(Connection connection, RiskEventAuditRecord event) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO mcace_risk_events(
                    event_id, session_id, player_uuid, event_type, weight, source,
                    origin, corroborated, observed_at, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb)
                """)) {
            statement.setObject(1, event.eventId());
            setNullableSession(statement, 2, event.sessionId());
            statement.setObject(3, event.playerId());
            statement.setString(4, event.type().name());
            statement.setInt(5, event.weight());
            statement.setString(6, event.source());
            statement.setString(7, event.origin().name());
            statement.setBoolean(8, event.corroborated());
            statement.setTimestamp(9, Timestamp.from(event.observedAt()));
            statement.setString(10, event.detailsJson());
            statement.executeUpdate();
        }
    }

    private static void insertRiskPolicyEvaluation(
            Connection connection, RiskPolicyEvaluation evaluation) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO mcace_risk_policy_evaluations(
                    event_id, applied_policy_version, baseline_policy_version,
                    candidate_policy_version, assigned_weight, baseline_weight,
                    candidate_weight, rollout_id, stage, cohort_bucket, evaluated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, evaluation.eventId());
            statement.setString(2, evaluation.appliedPolicyVersion());
            statement.setString(3, evaluation.baselinePolicyVersion());
            statement.setString(4, evaluation.candidatePolicyVersion());
            statement.setInt(5, evaluation.assignedWeight());
            statement.setInt(6, evaluation.baselineWeight());
            if (evaluation.candidateWeight() == null) statement.setNull(7, Types.INTEGER);
            else statement.setInt(7, evaluation.candidateWeight());
            if (evaluation.rolloutId() == null) statement.setNull(8, Types.OTHER);
            else statement.setObject(8, evaluation.rolloutId());
            statement.setString(9, evaluation.stage().name());
            statement.setInt(10, evaluation.cohortBucket());
            statement.setTimestamp(11, Timestamp.from(evaluation.evaluatedAt()));
            statement.executeUpdate();
        }
    }

    private static long nextPolicyRolloutSequence(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "SELECT nextval('mcace_policy_rollout_sequence')");
             ResultSet result = statement.executeQuery()) {
            if (!result.next()) throw new SQLException("policy rollout sequence is unavailable");
            return result.getLong(1);
        }
    }

    private static void insertPolicyRollout(
            Connection connection, long sequence, PolicyRolloutDraft draft, Instant createdAt)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO mcace_policy_rollouts(
                    sequence, rollout_id, policy_id, stage, percentage, reason, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setLong(1, sequence);
            statement.setObject(2, draft.rolloutId());
            statement.setObject(3, draft.policyId());
            statement.setString(4, draft.stage().name());
            statement.setInt(5, draft.percentage());
            statement.setString(6, draft.reason());
            statement.setString(7, draft.createdBy());
            statement.setTimestamp(8, Timestamp.from(createdAt));
            statement.executeUpdate();
        }
    }

    private static StoredPolicyRollout findLatestPolicyRollout(Connection connection, UUID policyId)
            throws SQLException {
        String sql = policyId == null
                ? """
                  SELECT sequence, rollout_id, policy_id, stage, percentage, reason, created_by, created_at
                  FROM mcace_policy_rollouts ORDER BY sequence DESC LIMIT 1
                  """
                : """
                  SELECT sequence, rollout_id, policy_id, stage, percentage, reason, created_by, created_at
                  FROM mcace_policy_rollouts WHERE policy_id = ? ORDER BY sequence DESC LIMIT 1
                  """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            if (policyId != null) statement.setObject(1, policyId);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? readPolicyRollout(result) : null;
            }
        }
    }

    private static StoredRiskPolicyRelease findLatestFullPolicyRelease(Connection connection)
            throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT policy_id FROM mcace_policy_rollouts
                WHERE stage = 'FULL' ORDER BY sequence DESC LIMIT 1
                """);
             ResultSet result = statement.executeQuery()) {
            return result.next() ? findRiskPolicyRelease(
                    connection, result.getObject(1, UUID.class)) : null;
        }
    }

    private static StoredRiskPolicyRelease findRiskPolicyRelease(Connection connection, UUID policyId)
            throws SQLException {
        RiskPolicyReleaseDraft draft;
        Instant createdAt;
        byte[] digest;
        String version;
        int watch;
        int restricted;
        int investigation;
        String description;
        String createdBy;
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT version, watch_threshold, restricted_threshold, investigation_threshold,
                       description, created_by, created_at, release_sha256
                FROM mcace_risk_policy_releases WHERE policy_id = ?
                """)) {
            statement.setObject(1, policyId);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) return null;
                version = result.getString(1);
                watch = result.getInt(2);
                restricted = result.getInt(3);
                investigation = result.getInt(4);
                description = result.getString(5);
                createdBy = result.getString(6);
                createdAt = result.getTimestamp(7).toInstant();
                digest = result.getBytes(8);
            }
        }
        EnumMap<RiskEventType, Integer> weights = new EnumMap<>(RiskEventType.class);
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT event_type, weight FROM mcace_risk_policy_weights WHERE policy_id = ?
                """)) {
            statement.setObject(1, policyId);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    weights.put(RiskEventType.valueOf(result.getString(1)), result.getInt(2));
                }
            }
        }
        draft = new RiskPolicyReleaseDraft(
                policyId, new RiskPolicy(version, weights, watch, restricted, investigation),
                description, createdBy);
        if (!MessageDigest.isEqual(digest, RiskPolicyReleaseCodec.hash(draft))) {
            throw new SQLException("risk policy release digest mismatch");
        }
        return new StoredRiskPolicyRelease(draft, createdAt, digest);
    }

    private static StoredPolicyRollout readPolicyRollout(ResultSet result) throws SQLException {
        return new StoredPolicyRollout(
                result.getLong(1),
                new PolicyRolloutDraft(
                        result.getObject(2, UUID.class), result.getObject(3, UUID.class),
                        PolicyRolloutStage.valueOf(result.getString(4)), result.getInt(5),
                        result.getString(6), result.getString(7)),
                result.getTimestamp(8).toInstant());
    }

    private static void validateRolloutTransition(
            StoredPolicyRollout current,
            StoredPolicyRollout global,
            PolicyRolloutDraft next) {
        if (global != null && !global.draft().policyId().equals(next.policyId())
                && (global.draft().stage() == PolicyRolloutStage.SHADOW
                || global.draft().stage() == PolicyRolloutStage.CANARY
                || global.draft().stage() == PolicyRolloutStage.BROAD)) {
            throw new WorkflowConflictException(
                    WorkflowConflictException.Kind.INVALID_TRANSITION,
                    "another policy candidate is already in rollout");
        }
        if (current == null) {
            if (next.stage() != PolicyRolloutStage.SHADOW) {
                throw new WorkflowConflictException(
                        WorkflowConflictException.Kind.INVALID_TRANSITION,
                        "a policy rollout must begin in SHADOW");
            }
            return;
        }
        PolicyRolloutStage from = current.draft().stage();
        PolicyRolloutStage to = next.stage();
        boolean permitted = switch (from) {
            case SHADOW -> to == PolicyRolloutStage.CANARY
                    || to == PolicyRolloutStage.PAUSED || to == PolicyRolloutStage.ROLLED_BACK;
            case CANARY -> (to == PolicyRolloutStage.CANARY
                    && next.percentage() >= current.draft().percentage())
                    || to == PolicyRolloutStage.BROAD
                    || to == PolicyRolloutStage.PAUSED || to == PolicyRolloutStage.ROLLED_BACK;
            case BROAD -> (to == PolicyRolloutStage.BROAD
                    && next.percentage() >= current.draft().percentage())
                    || to == PolicyRolloutStage.FULL
                    || to == PolicyRolloutStage.PAUSED || to == PolicyRolloutStage.ROLLED_BACK;
            case PAUSED -> to == PolicyRolloutStage.SHADOW || to == PolicyRolloutStage.ROLLED_BACK;
            case FULL, ROLLED_BACK, BASELINE -> false;
        };
        if (!permitted) {
            throw new WorkflowConflictException(
                    WorkflowConflictException.Kind.INVALID_TRANSITION,
                    "policy rollout transition is not permitted");
        }
    }

    private static void purgeExpiredWebCredentials(Connection connection, Instant activeAt)
            throws SQLException {
        try (PreparedStatement handoffs = connection.prepareStatement(
                "DELETE FROM mcace_web_handoffs WHERE expires_at <= ?")) {
            handoffs.setTimestamp(1, Timestamp.from(activeAt));
            handoffs.executeUpdate();
        }
        try (PreparedStatement sessions = connection.prepareStatement(
                "DELETE FROM mcace_web_sessions WHERE expires_at <= ?")) {
            sessions.setTimestamp(1, Timestamp.from(activeAt));
            sessions.executeUpdate();
        }
    }

    private static java.sql.Array roleArray(Connection connection, Set<WebRole> roles)
            throws SQLException {
        String[] values = roles.stream().map(Enum::name).sorted().toArray(String[]::new);
        return connection.createArrayOf("text", values);
    }

    private static Set<WebRole> readRoles(ResultSet result, int column) throws SQLException {
        java.sql.Array array = result.getArray(column);
        try {
            Object raw = array.getArray();
            Object[] values = (Object[]) raw;
            java.util.HashSet<WebRole> roles = new java.util.HashSet<>();
            for (Object value : values) roles.add(WebRole.valueOf(value.toString()));
            return Set.copyOf(roles);
        } finally {
            array.free();
        }
    }

    private static WebSessionHandoff readWebHandoff(ResultSet result) throws SQLException {
        return new WebSessionHandoff(
                result.getObject(1, UUID.class), result.getBytes(2),
                WebPrincipalType.valueOf(result.getString(3)), result.getString(4), readRoles(result, 5),
                result.getString(6), result.getString(7), result.getTimestamp(8).toInstant(),
                result.getTimestamp(9).toInstant());
    }

    private static StoredWebSession readWebSession(ResultSet result) throws SQLException {
        return new StoredWebSession(
                result.getObject(1, UUID.class), result.getBytes(2),
                WebPrincipalType.valueOf(result.getString(3)), result.getString(4), readRoles(result, 5),
                result.getString(6), result.getTimestamp(7).toInstant(), result.getTimestamp(8).toInstant());
    }

    private static PlayerNotification readPlayerNotification(ResultSet result) throws SQLException {
        Timestamp readAt = result.getTimestamp(9);
        return new PlayerNotification(
                result.getObject(1, UUID.class), result.getObject(2, UUID.class), result.getString(3),
                result.getString(4), result.getString(5), result.getString(6), result.getString(7),
                result.getTimestamp(8).toInstant(), readAt == null ? null : readAt.toInstant());
    }

    private static void insertPlayerNotification(
            Connection connection,
            UUID playerId,
            String type,
            String subjectId,
            String title,
            String message,
            String createdBy,
            Instant createdAt) throws SQLException {
        PlayerNotification notification = new PlayerNotification(
                UUID.randomUUID(), playerId, type, subjectId, title, message, createdBy, createdAt, null);
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO mcace_player_notifications(
                    notification_id, player_uuid, type, subject_id, title, message, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, notification.notificationId());
            statement.setObject(2, notification.playerId());
            statement.setString(3, notification.type());
            statement.setString(4, notification.subjectId());
            statement.setString(5, notification.title());
            statement.setString(6, notification.message());
            statement.setString(7, notification.createdBy());
            statement.setTimestamp(8, Timestamp.from(notification.createdAt()));
            statement.executeUpdate();
        }
    }

    private static void requireSha256(byte[] value) {
        Objects.requireNonNull(value, "secretSha256");
        if (value.length != 32) throw new IllegalArgumentException("secretSha256 must contain 32 bytes");
    }

    private static void requireWorkflowAudit(
            String actorId,
            OperatorAuditRecord audit,
            String action,
            String targetType,
            UUID targetId) {
        Objects.requireNonNull(audit, "audit");
        if (!actorId.equals(audit.actorId())
                || !action.equals(audit.action())
                || !targetType.equals(audit.targetType())
                || !targetId.toString().equals(audit.targetId())) {
            throw new IllegalArgumentException("workflow and audit action, identity, or target differ");
        }
    }

    private static void insertReviewTransition(
            Connection connection,
            UUID transitionId,
            UUID caseId,
            ReviewStatus from,
            ReviewStatus to,
            long version,
            String actorId,
            String reason,
            String recommendation,
            Instant occurredAt) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO mcace_review_transitions(
                    transition_id, case_id, from_status, to_status, resulting_version,
                    actor_id, reason, recommendation, occurred_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, transitionId);
            statement.setObject(2, caseId);
            if (from == null) statement.setNull(3, Types.VARCHAR);
            else statement.setString(3, from.name());
            statement.setString(4, to.name());
            statement.setLong(5, version);
            statement.setString(6, actorId);
            statement.setString(7, reason);
            statement.setString(8, recommendation);
            statement.setTimestamp(9, Timestamp.from(occurredAt));
            statement.executeUpdate();
        }
    }

    private static void insertAppealTransition(
            Connection connection,
            UUID transitionId,
            UUID appealId,
            AppealStatus from,
            AppealStatus to,
            long version,
            String actorId,
            String reason,
            Instant occurredAt) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                INSERT INTO mcace_appeal_transitions(
                    transition_id, appeal_id, from_status, to_status, resulting_version,
                    actor_id, reason, occurred_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            statement.setObject(1, transitionId);
            statement.setObject(2, appealId);
            if (from == null) statement.setNull(3, Types.VARCHAR);
            else statement.setString(3, from.name());
            statement.setString(4, to.name());
            statement.setLong(5, version);
            statement.setString(6, actorId);
            statement.setString(7, reason);
            statement.setTimestamp(8, Timestamp.from(occurredAt));
            statement.executeUpdate();
        }
    }

    private static StoredReviewCase lockReviewCase(Connection connection, UUID caseId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT case_id, player_uuid, title, reason, created_by, status,
                       recommendation, resolution, version, created_at, updated_at
                FROM mcace_review_cases WHERE case_id = ? FOR UPDATE
                """)) {
            statement.setObject(1, caseId);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new WorkflowConflictException(WorkflowConflictException.Kind.NOT_FOUND,
                            "review case does not exist");
                }
                return readReviewCase(result);
            }
        }
    }

    private static StoredAppeal lockAppeal(Connection connection, UUID appealId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT appeal_id, case_id, player_uuid, statement, submitted_by, status,
                       decision_reason, version, created_at, updated_at
                FROM mcace_appeals WHERE appeal_id = ? FOR UPDATE
                """)) {
            statement.setObject(1, appealId);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new WorkflowConflictException(WorkflowConflictException.Kind.NOT_FOUND,
                            "appeal does not exist");
                }
                return readAppeal(result);
            }
        }
    }

    private static List<SessionAuditRecord> findPlayerSessions(
            Connection connection, UUID playerId, int limit) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT session_id, player_uuid, server_id, policy_version, policy_sequence,
                       stage, trust_level, admission_status, risk_score, risk_band,
                       client_build_id, minecraft_version, loader, started_at, updated_at, expires_at
                FROM mcace_sessions WHERE player_uuid = ? ORDER BY updated_at DESC, session_id LIMIT ?
                """)) {
            statement.setObject(1, playerId);
            statement.setInt(2, limit);
            try (ResultSet result = statement.executeQuery()) {
                List<SessionAuditRecord> values = new ArrayList<>();
                while (result.next()) values.add(readSession(result));
                return List.copyOf(values);
            }
        }
    }

    private static List<RiskEventAuditRecord> findPlayerRiskEvents(
            Connection connection, UUID playerId, int limit) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT event_id, COALESCE(session_id, ''), player_uuid, event_type, weight,
                       source, origin, corroborated, observed_at, details::text
                FROM mcace_risk_events WHERE player_uuid = ?
                ORDER BY observed_at DESC, event_id LIMIT ?
                """)) {
            statement.setObject(1, playerId);
            statement.setInt(2, limit);
            try (ResultSet result = statement.executeQuery()) {
                List<RiskEventAuditRecord> values = new ArrayList<>();
                while (result.next()) values.add(readRiskEvent(result));
                return List.copyOf(values);
            }
        }
    }

    private static List<RiskPolicyEvaluation> findPlayerPolicyEvaluations(
            Connection connection, UUID playerId, int limit) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT e.event_id, e.applied_policy_version, e.baseline_policy_version,
                       e.candidate_policy_version, e.assigned_weight, e.baseline_weight,
                       e.candidate_weight, e.rollout_id, e.stage, e.cohort_bucket, e.evaluated_at
                FROM mcace_risk_policy_evaluations e
                JOIN mcace_risk_events r ON r.event_id = e.event_id
                WHERE r.player_uuid = ? ORDER BY e.evaluated_at DESC, e.event_id LIMIT ?
                """)) {
            statement.setObject(1, playerId);
            statement.setInt(2, limit);
            try (ResultSet result = statement.executeQuery()) {
                List<RiskPolicyEvaluation> values = new ArrayList<>();
                while (result.next()) values.add(readRiskPolicyEvaluation(result));
                return List.copyOf(values);
            }
        }
    }

    private static List<StoredEvidenceMetadata> findPlayerEvidence(
            Connection connection, UUID playerId, int limit) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT chain_sequence, evidence_id, player_uuid, COALESCE(session_id, ''),
                       evidence_type, origin, captured_at, stored_at, content_size, content_sha256,
                       storage_uri, operator_id, previous_chain_sha256, chain_sha256,
                       server_signature, signer_key_id
                FROM mcace_evidence_metadata WHERE player_uuid = ?
                ORDER BY captured_at DESC, chain_sequence DESC LIMIT ?
                """)) {
            statement.setObject(1, playerId);
            statement.setInt(2, limit);
            try (ResultSet result = statement.executeQuery()) {
                List<StoredEvidenceMetadata> values = new ArrayList<>();
                while (result.next()) values.add(readEvidence(result));
                return List.copyOf(values);
            }
        }
    }

    private static List<StoredReviewCase> findPlayerReviews(
            Connection connection, UUID playerId, int limit) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT case_id, player_uuid, title, reason, created_by, status,
                       recommendation, resolution, version, created_at, updated_at
                FROM mcace_review_cases WHERE player_uuid = ?
                ORDER BY updated_at DESC, case_id LIMIT ?
                """)) {
            statement.setObject(1, playerId);
            statement.setInt(2, limit);
            try (ResultSet result = statement.executeQuery()) {
                List<StoredReviewCase> values = new ArrayList<>();
                while (result.next()) values.add(readReviewCase(result));
                return List.copyOf(values);
            }
        }
    }

    private static List<StoredAppeal> findPlayerAppeals(
            Connection connection, UUID playerId, int limit) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT appeal_id, case_id, player_uuid, statement, submitted_by, status,
                       decision_reason, version, created_at, updated_at
                FROM mcace_appeals WHERE player_uuid = ?
                ORDER BY updated_at DESC, appeal_id LIMIT ?
                """)) {
            statement.setObject(1, playerId);
            statement.setInt(2, limit);
            try (ResultSet result = statement.executeQuery()) {
                List<StoredAppeal> values = new ArrayList<>();
                while (result.next()) values.add(readAppeal(result));
                return List.copyOf(values);
            }
        }
    }

    private static List<WorkflowTimelineEvent> findWorkflowEvents(
            Connection connection, UUID playerId, int limit) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT event_id, player_uuid, kind, subject_id, from_status, to_status,
                       actor_id, reason, recommendation, occurred_at
                FROM (
                    SELECT rt.transition_id AS event_id, rc.player_uuid,
                           'REVIEW_TRANSITION' AS kind, rt.case_id AS subject_id,
                           COALESCE(rt.from_status, '') AS from_status, rt.to_status,
                           rt.actor_id, rt.reason, rt.recommendation, rt.occurred_at
                    FROM mcace_review_transitions rt
                    JOIN mcace_review_cases rc ON rc.case_id = rt.case_id
                    WHERE rc.player_uuid = ?
                    UNION ALL
                    SELECT at.transition_id AS event_id, a.player_uuid,
                           'APPEAL_TRANSITION' AS kind, at.appeal_id AS subject_id,
                           COALESCE(at.from_status, '') AS from_status, at.to_status,
                           at.actor_id, at.reason, '' AS recommendation, at.occurred_at
                    FROM mcace_appeal_transitions at
                    JOIN mcace_appeals a ON a.appeal_id = at.appeal_id
                    WHERE a.player_uuid = ?
                ) workflow
                ORDER BY occurred_at DESC, event_id LIMIT ?
                """)) {
            statement.setObject(1, playerId);
            statement.setObject(2, playerId);
            statement.setInt(3, limit);
            try (ResultSet result = statement.executeQuery()) {
                List<WorkflowTimelineEvent> values = new ArrayList<>();
                while (result.next()) {
                    values.add(new WorkflowTimelineEvent(
                            result.getObject(1, UUID.class), result.getObject(2, UUID.class),
                            result.getString(3), result.getObject(4, UUID.class), result.getString(5),
                            result.getString(6), result.getString(7), result.getString(8),
                            result.getString(9), result.getTimestamp(10).toInstant()));
                }
                return List.copyOf(values);
            }
        }
    }

    private static void bindSession(PreparedStatement statement, SessionAuditRecord session) throws SQLException {
        statement.setString(1, session.sessionId());
        statement.setObject(2, session.playerId());
        statement.setString(3, session.serverId());
        statement.setString(4, session.policyVersion());
        statement.setLong(5, session.policySequence());
        statement.setString(6, session.stage().name());
        statement.setString(7, session.trustLevel().name());
        statement.setString(8, session.admissionStatus().name());
        statement.setInt(9, session.riskScore());
        statement.setString(10, session.riskBand().name());
        statement.setString(11, session.clientBuildId());
        statement.setString(12, session.minecraftVersion());
        statement.setString(13, session.loader().name());
        statement.setTimestamp(14, Timestamp.from(session.startedAt()));
        statement.setTimestamp(15, Timestamp.from(session.updatedAt()));
        statement.setTimestamp(16, Timestamp.from(session.expiresAt()));
    }

    private static SessionAuditRecord readSession(ResultSet result) throws SQLException {
        return new SessionAuditRecord(
                result.getString(1), result.getObject(2, UUID.class), result.getString(3), result.getString(4),
                result.getLong(5), SessionStage.valueOf(result.getString(6)), TrustLevel.valueOf(result.getString(7)),
                AdmissionStatus.valueOf(result.getString(8)), result.getInt(9), RiskBand.valueOf(result.getString(10)),
                result.getString(11), result.getString(12), LoaderType.valueOf(result.getString(13)),
                result.getTimestamp(14).toInstant(), result.getTimestamp(15).toInstant(),
                result.getTimestamp(16).toInstant());
    }

    private static RiskEventAuditRecord readRiskEvent(ResultSet result) throws SQLException {
        return new RiskEventAuditRecord(
                result.getObject(1, UUID.class), result.getString(2), result.getObject(3, UUID.class),
                RiskEventType.valueOf(result.getString(4)), result.getInt(5), result.getString(6),
                ObservationOrigin.valueOf(result.getString(7)), result.getBoolean(8),
                result.getTimestamp(9).toInstant(), result.getString(10));
    }

    private static RiskPolicyEvaluation readRiskPolicyEvaluation(ResultSet result) throws SQLException {
        return new RiskPolicyEvaluation(
                result.getObject(1, UUID.class), result.getString(2), result.getString(3),
                result.getString(4), result.getInt(5), result.getInt(6),
                result.getObject(7, Integer.class), result.getObject(8, UUID.class),
                PolicyRolloutStage.valueOf(result.getString(9)), result.getInt(10),
                result.getTimestamp(11).toInstant());
    }

    private static StoredEvidenceMetadata readEvidence(ResultSet result) throws SQLException {
        EvidenceMetadataDraft draft = new EvidenceMetadataDraft(
                result.getObject(2, UUID.class), result.getObject(3, UUID.class), result.getString(4),
                EvidenceType.valueOf(result.getString(5)), ObservationOrigin.valueOf(result.getString(6)),
                result.getTimestamp(7).toInstant(), result.getLong(9), result.getBytes(10),
                result.getString(11), result.getString(12));
        return new StoredEvidenceMetadata(
                draft, result.getLong(1), result.getTimestamp(8).toInstant(), result.getBytes(13),
                result.getBytes(14), result.getBytes(15), result.getString(16));
    }

    private static StoredRevocation readRevocation(ResultSet result) throws SQLException {
        Timestamp expiry = result.getTimestamp(7);
        RevocationDraft draft = new RevocationDraft(
                result.getObject(2, UUID.class), RevocationSubjectType.valueOf(result.getString(3)),
                result.getString(4), result.getString(5), result.getTimestamp(6).toInstant(),
                expiry == null ? null : expiry.toInstant(), result.getString(8));
        return new StoredRevocation(
                draft, result.getLong(1), result.getTimestamp(9).toInstant(), result.getBytes(10),
                result.getBytes(11), result.getString(12));
    }

    private static StoredReviewCase readReviewCase(ResultSet result) throws SQLException {
        ReviewCaseDraft draft = new ReviewCaseDraft(
                result.getObject(1, UUID.class), result.getObject(2, UUID.class),
                result.getString(3), result.getString(4), result.getString(5));
        return new StoredReviewCase(
                draft, ReviewStatus.valueOf(result.getString(6)), result.getString(7),
                result.getString(8), result.getLong(9), result.getTimestamp(10).toInstant(),
                result.getTimestamp(11).toInstant());
    }

    private static StoredAppeal readAppeal(ResultSet result) throws SQLException {
        AppealDraft draft = new AppealDraft(
                result.getObject(1, UUID.class), result.getObject(2, UUID.class),
                result.getObject(3, UUID.class), result.getString(4), result.getString(5));
        return new StoredAppeal(
                draft, AppealStatus.valueOf(result.getString(6)), result.getString(7),
                result.getLong(8), result.getTimestamp(9).toInstant(),
                result.getTimestamp(10).toInstant());
    }

    private static void setNullableSession(PreparedStatement statement, int index, String sessionId)
            throws SQLException {
        if (sessionId.isBlank()) statement.setNull(index, Types.VARCHAR);
        else statement.setString(index, sessionId);
    }

    private static void rollback(Connection connection, Exception original) {
        try {
            connection.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private record ChainHead(long sequence, byte[] hash) {
        private ChainHead {
            hash = hash.clone();
        }
        @Override public byte[] hash() { return hash.clone(); }
    }

    private record AuditAnchorHead(long sequence, byte[] hash, Instant createdAt) {
        private AuditAnchorHead {
            hash = hash.clone();
        }
        @Override public byte[] hash() { return hash.clone(); }
    }

    private record DigestHead(long count, long maximumSequence, byte[] hash) {
        private DigestHead {
            hash = hash.clone();
        }
        @Override public byte[] hash() { return hash.clone(); }
    }

    private static final class DisabledRevocationSigner implements RevocationSigner {
        @Override public byte[] sign(byte[] payloadSha256) throws SecurityPersistenceException {
            throw new SecurityPersistenceException("revocation signing is not configured");
        }
        @Override public String keyId() { return "disabled"; }
    }

    private static final class DisabledAuditAnchorSigner implements AuditAnchorSigner {
        @Override public byte[] sign(byte[] anchorSha256) throws SecurityPersistenceException {
            throw new SecurityPersistenceException("audit anchor signing is not configured");
        }
        @Override public String keyId() { return "disabled"; }
    }
}
