package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.ArtifactType;
import com.ellan.mcace.core.disposition.Confidence;
import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.EvaluationContext;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.DetectionArtifactType;
import com.ellan.mcace.protocol.generated.DetectionConfidence;
import com.ellan.mcace.protocol.generated.DetectionMatchType;
import com.ellan.mcace.protocol.generated.DetectionRule;
import com.ellan.mcace.protocol.generated.DetectionSelector;
import com.ellan.mcace.protocol.generated.DispositionPolicyDocument;
import com.ellan.mcace.protocol.generated.SignedDispositionPolicyDocument;
import com.ellan.mcace.protocol.policy.DispositionPolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class TrustedDispositionAuthorizationRuntimeTest {
    private static final long NOW_MS = 1_786_118_400_000L;
    private static final Instant NOW = Instant.ofEpochMilli(NOW_MS);
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000001");

    @Test
    void administratorReviewIsPersistedBeforeHighImpactEventIsReturned() throws Exception {
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        SignedDispositionPolicyDocument signed = signed(identity, DispositionAction.QUARANTINE);
        ArrayList<TrustedDispositionAuthorizationRecord> records = new ArrayList<>();
        TrustedDispositionAuthorizationRuntime runtime = new TrustedDispositionAuthorizationRuntime(
                policyRuntime(identity, signed), records::add);

        AuthenticatedManifestDispositionEvent event = runtime.authorizeAdministratorReview(
                PLAYER, "session-a", context(), observation(ObservationOrigin.ADMIN_REVIEWED),
                "console", "CASE-42");

        assertEquals(DispositionAction.QUARANTINE, event.highestAction());
        assertEquals(ObservationOrigin.ADMIN_REVIEWED, event.authorityOrigin());
        assertEquals("CASE-42", event.reviewTicket().orElseThrow());
        assertTrue(event.authorizationId().isPresent());
        assertTrue(event.hasAdmissionEffect());
        assertEquals(event.authorizationId().orElseThrow(), records.getFirst().authorizationId());
        assertFalse(records.getFirst().winningRuleId().isEmpty());
        assertEquals(64, records.getFirst().sessionCommitmentSha256().length());
        assertEquals(64, records.getFirst().reviewInputCommitmentSha256().length());
        assertEquals(64, records.getFirst().executionContextCommitmentSha256().length());
        assertEquals(records.getFirst().executionContextCommitmentSha256(),
                event.authorizationContextCommitmentSha256().orElseThrow());
    }

    @Test
    void auditFailurePreventsAuthorizationAndUntrustedOriginIsRejected() throws Exception {
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        SignedDispositionPolicyDocument signed = signed(identity, DispositionAction.LIMIT);
        TrustedDispositionAuthorizationRuntime failing = new TrustedDispositionAuthorizationRuntime(
                policyRuntime(identity, signed), record -> { throw new IOException("disk unavailable"); });

        assertThrows(IOException.class, () -> failing.authorizeAdministratorReview(
                PLAYER, "session-a", context(), observation(ObservationOrigin.ADMIN_REVIEWED),
                "console", "CASE-42"));
        assertThrows(IllegalArgumentException.class, () -> failing.authorizeAdministratorReview(
                PLAYER, "session-a", context(), observation(ObservationOrigin.CLIENT_REPORTED),
                "console", "CASE-42"));
    }

    @Test
    void callerCannotMoveAReviewIntoAFutureRuleWindow() throws Exception {
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        SignedDispositionPolicyDocument signed = signed(
                identity, DispositionAction.LIMIT, NOW_MS + 60_000L, NOW_MS + 86_400_000L);
        TrustedDispositionAuthorizationRuntime runtime = new TrustedDispositionAuthorizationRuntime(
                policyRuntime(identity, signed), record -> { });
        EvaluationContext callerFuture = new EvaluationContext(
                PLAYER, "velocity", "lobby", null, null, Set.of(), NOW.plusSeconds(120));

        assertThrows(IllegalArgumentException.class, () -> runtime.authorizeAdministratorReview(
                PLAYER, "session-a", callerFuture,
                observation(ObservationOrigin.ADMIN_REVIEWED), "console", "CASE-42"));
    }

    @Test
    void authorizationCapturesTheClockOnlyAfterBlockedPolicyRefreshCompletes() throws Exception {
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        SignedDispositionPolicyDocument signed = signed(identity, DispositionAction.LIMIT);
        MutableClock clock = new MutableClock(NOW);
        CountDownLatch sourceEntered = new CountDownLatch(1);
        CountDownLatch releaseSource = new CountDownLatch(1);
        ArrayList<TrustedDispositionAuthorizationRecord> records = new ArrayList<>();
        TrustedDispositionAuthorizationRuntime runtime = new TrustedDispositionAuthorizationRuntime(
                blockingPolicyRuntime(identity, signed, clock, sourceEntered, releaseSource),
                records::add);
        Instant afterRefresh = NOW.plusSeconds(10);

        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<AuthenticatedManifestDispositionEvent> authorization = executor.submit(() ->
                    runtime.authorizeAdministratorReview(
                            PLAYER, "session-a", context(),
                            observation(ObservationOrigin.ADMIN_REVIEWED), "console", "CASE-42"));
            try {
                assertTrue(sourceEntered.await(2, TimeUnit.SECONDS));
                clock.set(afterRefresh);
            } finally {
                releaseSource.countDown();
            }

            AuthenticatedManifestDispositionEvent event = authorization.get(2, TimeUnit.SECONDS);
            assertEquals(afterRefresh, event.evaluatedAt());
            assertEquals(afterRefresh, records.getFirst().authorizedAt());
        }
    }

    @Test
    void authorizationRejectsDocumentOrWinningRuleExpiryDuringBlockedPolicyRefresh()
            throws Exception {
        assertExpiryDuringBlockedRefreshRejected(NOW.plusSeconds(5), NOW.plusSeconds(5));
        assertExpiryDuringBlockedRefreshRejected(NOW.plusSeconds(60), NOW.plusSeconds(5));
    }

    @Test
    void executionContextBindsBackendButNotEvaluationTimestamp() throws Exception {
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        SignedDispositionPolicyDocument signed = signed(identity, DispositionAction.LIMIT);
        TrustedDispositionAuthorizationRuntime runtime = new TrustedDispositionAuthorizationRuntime(
                policyRuntime(identity, signed), record -> { });

        AuthenticatedManifestDispositionEvent event = runtime.authorizeAdministratorReview(
                PLAYER, "session-a", context(), observation(ObservationOrigin.ADMIN_REVIEWED),
                "console", "CASE-CONTEXT");
        UUID authorizationId = event.authorizationId().orElseThrow();
        String commitment = event.authorizationContextCommitmentSha256().orElseThrow();
        EvaluationContext laterEvaluation = new EvaluationContext(
                PLAYER, "velocity", "lobby", null, null, Set.of(), NOW.plusSeconds(30));
        EvaluationContext changedBackend = new EvaluationContext(
                PLAYER, "velocity", "survival", null, null, Set.of(), NOW);

        assertTrue(TrustedDispositionCommitments.executionContextMatches(
                authorizationId, laterEvaluation, commitment));
        assertFalse(TrustedDispositionCommitments.executionContextMatches(
                authorizationId, changedBackend, commitment));
    }

    private static SharedProxyDispositionPolicyRuntime policyRuntime(
            KeyPair identity, SignedDispositionPolicyDocument signed) {
        return new SharedProxyDispositionPolicyRuntime(
                ProxyFamily.VELOCITY, () -> signed, identity.getPublic(), CLOCK, Duration.ofSeconds(30));
    }

    private static SharedProxyDispositionPolicyRuntime blockingPolicyRuntime(
            KeyPair identity,
            SignedDispositionPolicyDocument signed,
            Clock clock,
            CountDownLatch sourceEntered,
            CountDownLatch releaseSource) {
        return new SharedProxyDispositionPolicyRuntime(
                ProxyFamily.VELOCITY,
                () -> {
                    sourceEntered.countDown();
                    try {
                        if (!releaseSource.await(2, TimeUnit.SECONDS)) {
                            throw new com.ellan.mcace.protocol.policy.PolicyException(
                                    "test policy source release timed out");
                        }
                    } catch (InterruptedException exception) {
                        Thread.currentThread().interrupt();
                        throw new com.ellan.mcace.protocol.policy.PolicyException(
                                "test policy source interrupted", exception);
                    }
                    return signed;
                },
                identity.getPublic(), clock, Duration.ofSeconds(30));
    }

    private static void assertExpiryDuringBlockedRefreshRejected(
            Instant documentExpiresAt, Instant ruleExpiresAt) throws Exception {
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        SignedDispositionPolicyDocument signed = signed(
                identity, DispositionAction.LIMIT, NOW_MS - 1_000L,
                ruleExpiresAt.toEpochMilli(), documentExpiresAt.toEpochMilli());
        MutableClock clock = new MutableClock(NOW);
        CountDownLatch sourceEntered = new CountDownLatch(1);
        CountDownLatch releaseSource = new CountDownLatch(1);
        ArrayList<TrustedDispositionAuthorizationRecord> records = new ArrayList<>();
        TrustedDispositionAuthorizationRuntime runtime = new TrustedDispositionAuthorizationRuntime(
                blockingPolicyRuntime(identity, signed, clock, sourceEntered, releaseSource),
                records::add);

        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<AuthenticatedManifestDispositionEvent> authorization = executor.submit(() ->
                    runtime.authorizeAdministratorReview(
                            PLAYER, "session-a", context(),
                            observation(ObservationOrigin.ADMIN_REVIEWED), "console", "CASE-42"));
            try {
                assertTrue(sourceEntered.await(2, TimeUnit.SECONDS));
                clock.set(NOW.plusSeconds(6));
            } finally {
                releaseSource.countDown();
            }

            ExecutionException failure = assertThrows(
                    ExecutionException.class, () -> authorization.get(2, TimeUnit.SECONDS));
            assertTrue(failure.getCause() instanceof IllegalArgumentException);
            assertEquals("trusted authorization requires an active high-impact signed-policy decision",
                    failure.getCause().getMessage());
            assertTrue(records.isEmpty());
        }
    }

    private static SignedDispositionPolicyDocument signed(KeyPair identity, DispositionAction action)
            throws Exception {
        return signed(identity, action, NOW_MS - 1_000L, NOW_MS + 86_400_000L);
    }

    private static SignedDispositionPolicyDocument signed(
            KeyPair identity, DispositionAction action, long ruleEffectiveFrom, long ruleExpiresAt)
            throws Exception {
        return signed(identity, action, ruleEffectiveFrom, ruleExpiresAt, NOW_MS + 86_400_000L);
    }

    private static SignedDispositionPolicyDocument signed(
            KeyPair identity,
            DispositionAction action,
            long ruleEffectiveFrom,
            long ruleExpiresAt,
            long documentExpiresAt)
            throws Exception {
        DetectionRule rule = DetectionRule.newBuilder()
                .setRuleId("reviewed-exact-hash")
                .setRevision(1)
                .setPriority(100)
                .setSelector(DetectionSelector.newBuilder()
                        .setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_EXACT_SHA256)
                        .setSha256(ByteString.copyFrom(new byte[32])))
                .setConfidence(DetectionConfidence.DETECTION_CONFIDENCE_CONFIRMED)
                .setDefaultAction(switch (action) {
                    case LIMIT -> com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_LIMIT;
                    case QUARANTINE -> com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_QUARANTINE;
                    case DENY -> com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_DENY;
                    default -> throw new IllegalArgumentException("test requires a high-impact action");
                })
                .setIntroducedAtEpochMs(NOW_MS - 1_000)
                .setEffectiveFromEpochMs(ruleEffectiveFrom)
                .setExpiresAtEpochMs(ruleExpiresAt)
                .build();
        DispositionPolicyDocument document = DispositionPolicyDocument.newBuilder()
                .setSchemaVersion(1)
                .setPolicyId("trusted-review")
                .setVersion("trusted-review-1")
                .setSequence(1)
                .setIssuedAtEpochMs(NOW_MS - 1_000)
                .setEffectiveFromEpochMs(NOW_MS - 1_000)
                .setExpiresAtEpochMs(documentExpiresAt)
                .setRolloutStage("FULL")
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(identity.getPublic())))
                .addRules(rule)
                .build();
        return DispositionPolicyDocuments.sign(document, identity.getPrivate(), identity.getPublic());
    }

    private static EvaluationContext context() {
        return new EvaluationContext(PLAYER, "velocity", "lobby", null, null, Set.of(), NOW);
    }

    private static ArtifactObservation observation(ObservationOrigin origin) {
        return new ArtifactObservation(
                ArtifactType.MOD, "example.mod", "1.0.0", "00".repeat(32), Map.of(),
                origin, Confidence.CONFIRMED, false);
    }

    @Test
    void serverConfirmedCannotEnterThroughARawArtifactObservation() {
        assertFalse(java.util.Arrays.stream(
                        TrustedDispositionAuthorizationRuntime.class.getDeclaredMethods())
                .filter(method -> method.getName().equals("authorizeServerConfirmed"))
                .flatMap(method -> java.util.Arrays.stream(method.getParameterTypes()))
                .anyMatch(ArtifactObservation.class::equals));
    }

    @Test
    void serverConfirmationPersistsProviderBoundAuthorization() throws Exception {
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        SignedDispositionPolicyDocument signed = signed(identity, DispositionAction.QUARANTINE);
        ArrayList<TrustedDispositionAuthorizationRecord> records = new ArrayList<>();
        TrustedDispositionAuthorizationRuntime runtime = new TrustedDispositionAuthorizationRuntime(
                policyRuntime(identity, signed), records::add);
        ServerBehaviorObservation provider = new ServerBehaviorObservation(
                PLAYER, "session-a", "grim", "Simulation", NOW.minusSeconds(1));
        ArtifactObservation correlated = new ArtifactObservation(
                ArtifactType.MOD, "example.mod", "1.0.0", "00".repeat(32),
                Map.of("correlated_provider", "grim", "correlated_signal", "Simulation",
                        "client_origin", ObservationOrigin.CLIENT_REPORTED.name()),
                ObservationOrigin.SERVER_CONFIRMED, Confidence.CONFIRMED, false);

        AuthenticatedManifestDispositionEvent event = runtime.authorizeServerConfirmation(
                PLAYER, "session-a", context(),
                new ServerConfirmedDispositionInput(provider, correlated));

        assertEquals(ObservationOrigin.SERVER_CONFIRMED, event.authorityOrigin());
        assertTrue(event.hasAdmissionEffect());
        assertTrue(event.reviewTicket().isEmpty());
        assertEquals(ObservationOrigin.SERVER_CONFIRMED, records.getFirst().origin());
        assertTrue(records.getFirst().operatorId().isEmpty());
        assertEquals(64, records.getFirst().reviewInputCommitmentSha256().length());
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> current;

        private MutableClock(Instant initial) {
            current = new AtomicReference<>(initial);
        }

        private void set(Instant value) {
            current.set(value);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) {
                throw new IllegalArgumentException("test clock only supports UTC");
            }
            return this;
        }

        @Override
        public Instant instant() {
            return current.get();
        }
    }
}
