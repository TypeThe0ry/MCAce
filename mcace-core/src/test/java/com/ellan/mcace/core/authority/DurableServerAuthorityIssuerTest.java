package com.ellan.mcace.core.authority;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class DurableServerAuthorityIssuerTest {
    private static final Set<String> FORBIDDEN_TERMS = Set.of(
            "origin", "confidence", "action", "rule", "route", "kick", "ban");

    @TempDir Path directory;

    @Test
    void releasesExactFrameOnlyAfterForcedContentFreeRecord() throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        ServerAuthorityObservationCodec codec = new ServerAuthorityObservationCodec(
                AuthorityTestFixtures.CLOCK, new SecureRandom());
        Path path = directory.resolve("issuance.log");
        AuthorityJournalTestFixture.initializeEmpty(path);

        DurablyIssuedServerAuthorityObservation issued;
        try (DurableServerAuthorityIssuer issuer = new DurableServerAuthorityIssuer(
                codec, backendKeys, path, 8192)) {
            RecoveredServerAuthoritySequence recovered = issuer.recover(
                    AuthorityTestFixtures.verifiedGrant());
            assertEquals(0L, recovered.lastSequence());
            assertTrue(recovered.matches(AuthorityTestFixtures.verifiedGrant()));
            issued = issueNext(issuer, backendKeys);
            assertEquals(1L, issuer.recover(
                    AuthorityTestFixtures.verifiedGrant()).lastSequence());
        }

        assertEquals(1L, issued.observationSequence());
        assertTrue(issued.matches(AuthorityTestFixtures.verifiedGrant()));
        assertFalse(issued.matches(AuthorityTestFixtures.verifiedGrant(
                AuthorityTestFixtures.PLAYER, AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.BACKEND_INSTANCE, java.util.UUID.randomUUID(),
                AuthorityTestFixtures.GRANT_COMMITMENT, AuthorityTestFixtures.binding(),
                AuthorityTestFixtures.ADMISSION_SEQUENCE,
                AuthorityTestFixtures.NOW.minusSeconds(10),
                AuthorityTestFixtures.NOW.plusSeconds(20))));
        String raw = Files.readString(path, StandardCharsets.UTF_8);
        assertTrue(raw.contains(issued.attestationId().toString()));
        assertTrue(raw.contains(issued.signedFrameSha256()));
        assertFalse(raw.contains(AuthorityTestFixtures.SESSION));
        assertFalse(raw.contains(AuthorityTestFixtures.PLAYER.toString()));
        VerifiedServerAuthorityObservation verified = codec.verify(
                issued.frame(), AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.PLAYER, AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.binding(), AuthorityTestFixtures.ADMISSION_SEQUENCE,
                AuthorityTestFixtures.verifiedGrant(), java.util.Optional.empty(),
                AuthorityTestFixtures.registry(backendKeys), AuthorityTestFixtures.replayGuard());
        assertEquals(issued.attestationId(), verified.attestationId());
        assertEquals(1L, verified.observationSequence());
        assertEquals(issued.signedFrameSha256(), verified.signedFrameSha256());
        byte[] copy = issued.frame();
        copy[0] ^= 1;
        assertFalse(Arrays.equals(copy, issued.frame()));
    }

    @Test
    void restartAllocatesFromTheLastDurableLifecycleSequence() throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        ServerAuthorityObservationCodec codec = new ServerAuthorityObservationCodec(
                AuthorityTestFixtures.CLOCK, new SecureRandom());
        Path path = directory.resolve("restart.log");
        AuthorityJournalTestFixture.initializeEmpty(path);

        try (DurableServerAuthorityIssuer first = new DurableServerAuthorityIssuer(
                codec, backendKeys, path, 8192)) {
            assertEquals(1L, issueNext(first, backendKeys).observationSequence());
        }
        try (DurableServerAuthorityIssuer restarted = new DurableServerAuthorityIssuer(
                codec, backendKeys, path, 8192)) {
            assertEquals(2L, issueNext(restarted, backendKeys).observationSequence());
        }

        String lifecycle = AuthorityIssuanceCommitments.lifecycle(
                AuthorityTestFixtures.observationRequest(backendKeys));
        try (FileServerAuthorityIssuanceJournal recovered =
                     new FileServerAuthorityIssuanceJournal(path, 8192)) {
            assertEquals(2L, recovered.lastSequence(lifecycle));
        }
    }

    @Test
    void journalFailureReturnsNoTokenAndDoesNotPreconsumeTheSequence() throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        ServerAuthorityObservationCodec codec = new ServerAuthorityObservationCodec(
                AuthorityTestFixtures.CLOCK, new SecureRandom());
        FailOnceJournal journal = new FailOnceJournal();
        DurableServerAuthorityIssuer unavailable = new DurableServerAuthorityIssuer(
                codec, backendKeys, journal);

        assertThrows(IOException.class, () -> issueNext(unavailable, backendKeys));
        assertThrows(IOException.class, () -> issueNext(unavailable, backendKeys));
        assertEquals(List.of(1L), journal.attemptedSequences);
        DurableServerAuthorityIssuer retry = new DurableServerAuthorityIssuer(
                codec, backendKeys, journal);
        DurablyIssuedServerAuthorityObservation issued = issueNext(retry, backendKeys);

        assertEquals(List.of(1L, 1L), journal.attemptedSequences);
        assertEquals(1L, journal.committedSequence);
        assertEquals(1L, issued.observationSequence());
    }

    @Test
    void recoveryIoFailurePermanentlyPoisonsThatIssuerInstance() throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        ServerAuthorityObservationCodec codec = new ServerAuthorityObservationCodec(
                AuthorityTestFixtures.CLOCK, new SecureRandom());
        FailRecoveryJournal journal = new FailRecoveryJournal();
        DurableServerAuthorityIssuer issuer = new DurableServerAuthorityIssuer(
                codec, backendKeys, journal);

        assertThrows(IOException.class,
                () -> issuer.recover(AuthorityTestFixtures.verifiedGrant()));
        assertThrows(IOException.class, () -> issueNext(issuer, backendKeys));
        assertEquals(1, journal.recoveryAttempts);
        assertEquals(0, journal.appendAttempts);
    }

    @Test
    void journalRuntimeFailurePermanentlyPoisonsThatIssuerInstance() throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        ServerAuthorityObservationCodec codec = new ServerAuthorityObservationCodec(
                AuthorityTestFixtures.CLOCK, new SecureRandom());
        RuntimeFailureJournal journal = new RuntimeFailureJournal();
        DurableServerAuthorityIssuer issuer = new DurableServerAuthorityIssuer(
                codec, backendKeys, journal);

        assertThrows(IllegalStateException.class, () -> issueNext(issuer, backendKeys));
        assertThrows(IOException.class, () -> issueNext(issuer, backendKeys));
        assertEquals(1, journal.appendAttempts);
    }

    @Test
    void keyMismatchFailsBeforeJournalInspectionOrAppend() throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        KeyPair other = AuthorityTestFixtures.keyPair();
        ServerAuthorityObservationCodec codec = new ServerAuthorityObservationCodec(
                AuthorityTestFixtures.CLOCK, new SecureRandom());
        AtomicReference<String> inspected = new AtomicReference<>();
        AtomicReference<ServerAuthorityIssuanceRecord> appended = new AtomicReference<>();
        ServerAuthorityIssuanceJournal journal = new ServerAuthorityIssuanceJournal() {
            @Override
            public void appendAndForce(ServerAuthorityIssuanceRecord record) {
                appended.set(record);
            }

            @Override
            public long lastSequence(String lifecycleCommitmentSha256) {
                inspected.set(lifecycleCommitmentSha256);
                return 0L;
            }
        };
        DurableServerAuthorityIssuer pinned = new DurableServerAuthorityIssuer(
                codec, backendKeys, journal);

        assertThrows(AuthorityProtocolException.class,
                () -> pinned.issue(AuthorityTestFixtures.verifiedGrant(), 1L,
                        AuthorityTestFixtures.observationRequest(other)));
        assertNull(inspected.get());
        assertNull(appended.get());

        ServerAuthorityObservationCodec.ObservationRequest base =
                AuthorityTestFixtures.observationRequest(backendKeys)
                        .withObservationSequence(1L);
        ServerAuthorityObservationCodec.ProviderInput preGrantProvider =
                new ServerAuthorityObservationCodec.ProviderInput(
                        "grim-domain", "grim", "1.0.0", "movement-stable", 2, 3,
                        AuthorityTestFixtures.NOW.minusSeconds(11),
                        AuthorityTestFixtures.NOW.minusSeconds(2));
        ServerAuthorityObservationCodec.ObservationRequest preGrantWindow =
                new ServerAuthorityObservationCodec.ObservationRequest(
                        base.backendInstanceId(), base.backendKeyIdSha256(), base.playerId(),
                        base.authenticatedSessionId(), base.grantId(),
                        base.grantCommitmentSha256(), base.physicalLoginBinding(),
                        base.admissionTransportSequence(), base.observationSequence(),
                        base.observedAt(), base.lifetime(), base.authorityProfileSha256(),
                        List.of(preGrantProvider, AuthorityTestFixtures.providers().get(1)));
        assertThrows(AuthorityProtocolException.class,
                () -> pinned.issue(
                        AuthorityTestFixtures.verifiedGrant(), 1L, preGrantWindow));
        assertNull(inspected.get());
        assertNull(appended.get());

        assertEquals(1L, issueNext(pinned, backendKeys).observationSequence());
        assertTrue(inspected.get() != null);
        assertTrue(appended.get() != null);
    }

    @Test
    void staleExpectedSequenceFailsBeforeSigningOrAppendAndDoesNotPoisonIssuer()
            throws Exception {
        KeyPair backendKeys = AuthorityTestFixtures.keyPair();
        ServerAuthorityObservationCodec codec = new ServerAuthorityObservationCodec(
                AuthorityTestFixtures.CLOCK, new SecureRandom());
        AtomicReference<ServerAuthorityIssuanceRecord> appended = new AtomicReference<>();
        ServerAuthorityIssuanceJournal journal = new ServerAuthorityIssuanceJournal() {
            @Override
            void appendAndForce(ServerAuthorityIssuanceRecord record) {
                appended.set(record);
            }

            @Override
            long lastSequence(String lifecycleCommitmentSha256) {
                return 1L;
            }
        };
        DurableServerAuthorityIssuer issuer = new DurableServerAuthorityIssuer(
                codec, backendKeys, journal);
        BackendAuthorityGrantCodec.VerifiedGrant grant = AuthorityTestFixtures.verifiedGrant();
        ServerAuthorityObservationCodec.ObservationRequest stale =
                AuthorityTestFixtures.observationRequest(backendKeys)
                        .withObservationSequence(1L);

        assertThrows(AuthoritySequenceMismatchException.class,
                () -> issuer.issue(grant, 1L, stale));
        assertNull(appended.get());
        ServerAuthorityObservationCodec.ObservationRequest current =
                stale.withObservationSequence(2L);
        assertEquals(2L, issuer.issue(grant, 2L, current).observationSequence());
        assertTrue(appended.get() != null);
    }

    @Test
    void rawSignerJournalImplementationRecordAndDurableTokenAreNotPublicSeams()
            throws Exception {
        assertFalse(Modifier.isPublic(ServerAuthorityObservationCodec.class
                .getDeclaredMethod("sign", ServerAuthorityObservationCodec.ObservationRequest.class,
                        java.security.PrivateKey.class).getModifiers()));
        assertFalse(Modifier.isPublic(FileServerAuthorityIssuanceJournal.class.getModifiers()));
        assertFalse(Modifier.isPublic(ServerAuthorityIssuanceRecord.class.getModifiers()));
        assertTrue(Arrays.stream(ServerAuthorityIssuanceRecord.class.getDeclaredConstructors())
                .noneMatch(constructor -> Modifier.isPublic(constructor.getModifiers())));
        assertTrue(AutoCloseable.class.isAssignableFrom(DurableServerAuthorityIssuer.class));
        assertTrue(Arrays.stream(DurablyIssuedServerAuthorityObservation.class
                        .getDeclaredConstructors())
                .noneMatch(constructor -> Modifier.isPublic(constructor.getModifiers())));
        assertFalse(Modifier.isPublic(DurablyIssuedServerAuthorityObservation.class
                .getDeclaredMethod("frame").getModifiers()));
        assertTrue(Arrays.stream(RecoveredServerAuthoritySequence.class
                        .getDeclaredConstructors())
                .noneMatch(constructor -> Modifier.isPublic(constructor.getModifiers())));
        assertTrue(Modifier.isAbstract(ServerAuthorityIssuanceJournal.class.getModifiers()));
        assertTrue(Arrays.stream(DurableServerAuthorityIssuer.class.getConstructors())
                .anyMatch(constructor -> Arrays.equals(constructor.getParameterTypes(),
                        new Class<?>[] {ServerAuthorityObservationCodec.class, KeyPair.class,
                                Path.class, long.class})));
        assertThrows(NoSuchMethodException.class, () ->
                DurableServerAuthorityIssuer.class.getMethod(
                        "lastSequence", ServerAuthorityObservationCodec.ObservationRequest.class));
        assertThrows(NoSuchMethodException.class, () ->
                DurableServerAuthorityIssuer.class.getMethod(
                        "issue", ServerAuthorityObservationCodec.ObservationRequest.class));
        assertTrue(Modifier.isPublic(DurableServerAuthorityIssuer.class.getMethod(
                "issue", BackendAuthorityGrantCodec.VerifiedGrant.class, long.class,
                ServerAuthorityObservationCodec.ObservationRequest.class).getModifiers()));
        assertTrue(Modifier.isPublic(ServerAuthorityJournalPreflight.class.getModifiers()));
        Arrays.stream(DurablyIssuedServerAuthorityObservation.class.getDeclaredFields())
                .map(field -> field.getName().toLowerCase(Locale.ROOT))
                .forEach(name -> FORBIDDEN_TERMS.forEach(term ->
                        assertFalse(name.contains(term), name + " exposes " + term)));
        Arrays.stream(DurablyIssuedServerAuthorityObservation.class.getDeclaredMethods())
                .filter(method -> Modifier.isPublic(method.getModifiers()))
                .map(method -> method.getName().toLowerCase(Locale.ROOT))
                .forEach(name -> FORBIDDEN_TERMS.forEach(term ->
                        assertFalse(name.contains(term), name + " exposes " + term)));
    }

    @Test
    void issuerRejectsMismatchedKeyPair() throws Exception {
        KeyPair first = AuthorityTestFixtures.keyPair();
        KeyPair second = AuthorityTestFixtures.keyPair();
        KeyPair mismatched = new KeyPair(first.getPublic(), second.getPrivate());
        ServerAuthorityObservationCodec codec = new ServerAuthorityObservationCodec(
                AuthorityTestFixtures.CLOCK, new SecureRandom());
        assertThrows(IllegalArgumentException.class, () -> new DurableServerAuthorityIssuer(
                codec, mismatched, new NoOpJournal()));
    }

    private static DurablyIssuedServerAuthorityObservation issueNext(
            DurableServerAuthorityIssuer issuer,
            KeyPair backendKeys) throws Exception {
        BackendAuthorityGrantCodec.VerifiedGrant grant = AuthorityTestFixtures.verifiedGrant();
        long sequence = Math.incrementExact(issuer.recover(grant).lastSequence());
        ServerAuthorityObservationCodec.ObservationRequest request =
                AuthorityTestFixtures.observationRequest(backendKeys)
                        .withObservationSequence(sequence);
        return issuer.issue(grant, sequence, request);
    }

    private static final class FailOnceJournal extends ServerAuthorityIssuanceJournal {
        private final List<Long> attemptedSequences = new ArrayList<>();
        private long committedSequence;

        @Override
        public void appendAndForce(ServerAuthorityIssuanceRecord record) throws IOException {
            attemptedSequences.add(record.observationSequence());
            if (attemptedSequences.size() == 1) {
                throw new IOException("unavailable");
            }
            committedSequence = record.observationSequence();
        }

        @Override
        public long lastSequence(String lifecycleCommitmentSha256) {
            return committedSequence;
        }
    }

    private static final class NoOpJournal extends ServerAuthorityIssuanceJournal {
        @Override
        void appendAndForce(ServerAuthorityIssuanceRecord record) {
        }

        @Override
        long lastSequence(String lifecycleCommitmentSha256) {
            return 0L;
        }
    }

    private static final class FailRecoveryJournal extends ServerAuthorityIssuanceJournal {
        private int recoveryAttempts;
        private int appendAttempts;

        @Override
        void appendAndForce(ServerAuthorityIssuanceRecord record) {
            appendAttempts++;
        }

        @Override
        long lastSequence(String lifecycleCommitmentSha256) throws IOException {
            recoveryAttempts++;
            throw new IOException("recovery unavailable");
        }
    }

    private static final class RuntimeFailureJournal extends ServerAuthorityIssuanceJournal {
        private int appendAttempts;

        @Override
        void appendAndForce(ServerAuthorityIssuanceRecord record) {
            appendAttempts++;
            throw new IllegalStateException("uncertain runtime failure");
        }

        @Override
        long lastSequence(String lifecycleCommitmentSha256) {
            return 0L;
        }
    }
}
