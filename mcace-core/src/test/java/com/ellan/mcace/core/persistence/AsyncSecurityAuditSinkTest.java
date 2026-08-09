package com.ellan.mcace.core.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.session.SessionStage;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.RiskBand;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

final class AsyncSecurityAuditSinkTest {
    @Test
    void preservesOrderAndReportsWorkerFailuresWithoutThrowingToCaller() throws Exception {
        List<String> operations = new CopyOnWriteArrayList<>();
        List<Exception> failures = new CopyOnWriteArrayList<>();
        SecurityAuditSink delegate = new SecurityAuditSink() {
            @Override public void upsertSession(SessionAuditRecord session) {
                operations.add(session.stage().name());
            }

            @Override public void appendRiskEvent(RiskEventAuditRecord event) throws SecurityPersistenceException {
                throw new SecurityPersistenceException("controlled worker failure");
            }

            @Override public StoredEvidenceMetadata appendEvidence(EvidenceMetadataDraft evidence) {
                throw new UnsupportedOperationException();
            }
        };

        try (AsyncSecurityAuditSink sink = new AsyncSecurityAuditSink(delegate, 8, failures::add)) {
            sink.upsertSession(session(SessionStage.CHALLENGE_SENT));
            sink.appendRiskEvent(new RiskEventAuditRecord(
                    UUID.randomUUID(), "session", UUID.randomUUID(),
                    com.ellan.mcace.core.risk.RiskEventType.UNKNOWN_MOD, 15, "test",
                    ObservationOrigin.CLIENT_REPORTED, false, Instant.EPOCH, "{}"));
            sink.upsertSession(session(SessionStage.AUTHENTICATED));
            assertTrue(sink.flush(Duration.ofSeconds(2)));
        }

        assertEquals(List.of("CHALLENGE_SENT", "AUTHENTICATED"), operations);
        assertEquals(1, failures.size());
    }

    private static SessionAuditRecord session(SessionStage stage) {
        return new SessionAuditRecord(
                "session", UUID.randomUUID(), "server", "policy", 1, stage,
                stage == SessionStage.AUTHENTICATED ? TrustLevel.VERIFIED : TrustLevel.UNKNOWN,
                stage == SessionStage.AUTHENTICATED ? AdmissionStatus.VERIFIED : AdmissionStatus.VERIFYING,
                0, RiskBand.NORMAL, "", "", LoaderType.LOADER_UNSPECIFIED,
                Instant.EPOCH, Instant.EPOCH, Instant.EPOCH.plusSeconds(5));
    }
}
