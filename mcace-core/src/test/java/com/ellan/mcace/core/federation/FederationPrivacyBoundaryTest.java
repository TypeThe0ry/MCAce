package com.ellan.mcace.core.federation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class FederationPrivacyBoundaryTest {
    @TempDir Path temporaryDirectory;

    @Test
    void subjectDefensivelyCopiesSessionBindings() throws Exception {
        KeyPair client = Ed25519Keys.generate(new SecureRandom());
        byte[] challenge = new byte[32];
        byte[] policy = new byte[32];
        challenge[0] = 1;
        policy[0] = 2;
        FederationSubject subject = new FederationSubject(
                UUID.randomUUID(), "target-network", "target-session", client.getPublic(), challenge,
                "policy-v1", policy, Instant.parse("2026-08-09T00:00:00Z"));

        challenge[0] = 9;
        policy[0] = 9;
        assertTrue(subject.serverChallengeNonce()[0] == 1);
        assertTrue(subject.policySha256()[0] == 2);
        byte[] returned = subject.serverChallengeNonce();
        returned[0] = 7;
        assertTrue(subject.serverChallengeNonce()[0] == 1);
    }

    @Test
    void fileAuditIsBoundedAndContainsNoSessionChallengePolicyOrPresentation() throws Exception {
        Path audit = temporaryDirectory.resolve("federation-audit.log");
        FileFederationAuditSink sink = new FileFederationAuditSink(audit, 8192);
        FederationAuditRecord record = new FederationAuditRecord(
                Instant.parse("2026-08-09T00:00:00Z"), FederationAuditEvent.PRESENTATION_ACCEPTED,
                FederationAuditOutcome.SUCCEEDED, "velocity-console", UUID.randomUUID(),
                "source-network", "target-network", Optional.of(UUID.randomUUID()),
                Optional.of("ab".repeat(8)));

        sink.append(record);
        String line = Files.readString(audit, StandardCharsets.UTF_8);
        assertTrue(line.contains("PRESENTATION_ACCEPTED"));
        assertTrue(line.contains("velocity-console"));
        assertFalse(line.contains("target-session"));
        assertFalse(line.contains("policy-v1"));
        assertFalse(line.contains("presentation="));
        assertFalse(line.contains("challenge="));
        assertFalse(line.contains("ab".repeat(32)));
    }

    @Test
    void auditRecordRejectsCompletePeerPinAndAcceptsOnlyShortFingerprint() {
        assertThrows(IllegalArgumentException.class, () -> new FederationAuditRecord(
                Instant.parse("2026-08-09T00:00:00Z"), FederationAuditEvent.PRESENTATION_ACCEPTED,
                FederationAuditOutcome.SUCCEEDED, "velocity-console", UUID.randomUUID(),
                "source-network", "target-network", Optional.empty(), Optional.of("ab".repeat(32))));
        new FederationAuditRecord(
                Instant.parse("2026-08-09T00:00:00Z"), FederationAuditEvent.PRESENTATION_ACCEPTED,
                FederationAuditOutcome.SUCCEEDED, "velocity-console", UUID.randomUUID(),
                "source-network", "target-network", Optional.empty(), Optional.of("ab".repeat(8)));
    }
}
