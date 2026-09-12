package com.ellan.mcace.core.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.federation.FederationDocuments;
import com.ellan.mcace.protocol.federation.FederationException;
import com.ellan.mcace.protocol.federation.FederationVerification;
import com.ellan.mcace.protocol.generated.FederationGrant;
import com.ellan.mcace.protocol.generated.FederationLocalClaim;
import com.ellan.mcace.protocol.generated.FederationPresentation;
import com.ellan.mcace.protocol.generated.PacketType;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class FederationRuntimeTest {
    private static final Instant NOW = Instant.parse("2026-08-09T00:00:00Z");
    private static final String SOURCE = "source-network";
    private static final String TARGET = "target-network";

    @Test
    void completesClientCarriedRoundTripAsObserveOnlyWithoutPublishingLocalApi() throws Exception {
        Fixture fixture = fixture();
        InMemoryMCAceApi unrelatedLocalApi = new InMemoryMCAceApi();

        GrantExchange exchange = fixture.issueAndGrant();
        FederationPresentation presentation = fixture.presentation(exchange.grant(), fixture.targetSubject());
        FederationPresentationResult result = fixture.targetRuntime().receivePresentation(
                fixture.targetSubject(), fixture.outerPresentation(presentation, fixture.targetSubject()),
                "target-console");

        assertEquals(FederationRuntimeStatus.OBSERVED, result.status());
        FederationObservation observation = result.observation().orElseThrow();
        assertEquals(FederationLocalClaim.FEDERATION_SOURCE_LOCALLY_VERIFIED, observation.remoteClaim());
        assertEquals(SOURCE, observation.sourceNetworkId());
        assertEquals(TARGET, observation.targetNetworkId());
        assertEquals(1, fixture.targetRuntime().observations(fixture.playerId(), 10).size());
        assertTrue(unrelatedLocalApi.snapshot(fixture.playerId()).isEmpty());
        assertEquals(List.of(FederationAuditEvent.CONSENT_ISSUED, FederationAuditEvent.GRANT_SIGNED),
                fixture.sourceAudits().stream().map(FederationAuditRecord::event).toList());
        assertEquals(List.of(FederationAuditEvent.PRESENTATION_ACCEPTED),
                fixture.targetAudits().stream().map(FederationAuditRecord::event).toList());
    }

    @Test
    void rejectsTargetSessionWithoutSignedAssertionAuthBinding() throws Exception {
        Fixture fixture = fixture();
        FederationSubject preexistingTargetSession = fixture.targetSubject();
        fixture.clock().advance(Duration.ofSeconds(10));
        GrantExchange exchange = fixture.issueAndGrant();
        FederationPresentation presentation = fixture.presentation(
                exchange.grant(), preexistingTargetSession);

        FederationPresentationResult result = fixture.targetRuntime().receivePresentation(
                preexistingTargetSession,
                fixture.outerPresentation(presentation, preexistingTargetSession),
                "target-console");

        assertEquals(FederationRuntimeStatus.INVALID_PRESENTATION, result.status());
        assertTrue(result.observation().isEmpty());
        assertTrue(fixture.targetRuntime().observations(fixture.playerId(), 10).isEmpty());
        assertEquals(FederationAuditEvent.PRESENTATION_REJECTED,
                fixture.targetAudits().getLast().event());
    }

    @Test
    void exactAssertionBindingAcceptsDespiteIndependentTargetClockOrdering() throws Exception {
        Fixture fixture = fixture();
        FederationIssueResult issue = fixture.sourceRuntime().issueConsent(
                fixture.sourceSubject(), TARGET, "source-console");
        assertEquals(FederationRuntimeStatus.CONSENT_ISSUED, issue.status());

        fixture.clock().advance(Duration.ofSeconds(1));
        FederationSubject targetBetweenRequestAndGrant = new FederationSubject(
                fixture.playerId(), TARGET, "target-between-request-and-grant",
                fixture.client().getPublic(), fixture.targetChallenge(),
                fixture.sourceSubject().policyVersion(), fixture.sourceSubject().policySha256(),
                fixture.clock().instant());

        fixture.clock().advance(Duration.ofSeconds(1));
        var request = issue.request().orElseThrow();
        var consent = FederationDocuments.signClientConsent(
                request, fixture.client().getPrivate(), fixture.client().getPublic(),
                fixture.clock(), ProtocolConstants.DEFAULT_CLOCK_SKEW);
        EnvelopeCodec clientCodec = new EnvelopeCodec(
                fixture.clock(), new SecureRandom(),
                ProtocolConstants.MAX_FEDERATION_PRESENTATION_BYTES,
                ProtocolConstants.DEFAULT_CLOCK_SKEW);
        byte[] responseFrame = clientCodec.sign(
                PacketType.FEDERATION_CONSENT_RESPONSE,
                fixture.sourceSubject().authenticatedSessionId(),
                FederationDocuments.encodeConsentResponse(consent),
                fixture.client().getPrivate()).toByteArray();
        FederationGrant grant = fixture.sourceRuntime()
                .receiveConsentResponse(fixture.sourceSubject(), responseFrame)
                .grant().orElseThrow();
        FederationSubject exactlyBoundTarget = new FederationSubject(
                targetBetweenRequestAndGrant.playerId(), targetBetweenRequestAndGrant.localNetworkId(),
                targetBetweenRequestAndGrant.authenticatedSessionId(),
                targetBetweenRequestAndGrant.clientPublicKey(),
                targetBetweenRequestAndGrant.serverChallengeNonce(),
                targetBetweenRequestAndGrant.policyVersion(),
                targetBetweenRequestAndGrant.policySha256(),
                targetBetweenRequestAndGrant.authenticatedAt(),
                Optional.of(new FederationAuthenticationBinding(
                        FederationDocuments.signedAssertionSha256(grant))));
        FederationPresentation presentation = fixture.presentation(
                grant, exactlyBoundTarget);

        FederationPresentationResult result = fixture.targetRuntime().receivePresentation(
                exactlyBoundTarget,
                fixture.outerPresentation(presentation, exactlyBoundTarget),
                "target-console");

        assertEquals(FederationRuntimeStatus.OBSERVED, result.status());
        assertTrue(result.observation().isPresent());
        assertEquals(1, fixture.targetRuntime().observations(fixture.playerId(), 10).size());
        assertEquals(FederationAuditEvent.PRESENTATION_ACCEPTED,
                fixture.targetAudits().getLast().event());
    }

    @Test
    void wrongTargetAuthHashDoesNotBurnPresentationReplayBeforeCorrectBoundRetry() throws Exception {
        Fixture fixture = fixture();
        GrantExchange exchange = fixture.issueAndGrant();
        FederationSubject correct = fixture.targetSubject();
        byte[] wrongHash = correct.targetAuthenticationBinding().orElseThrow()
                .signedAssertionSha256();
        wrongHash[0] ^= 1;
        FederationSubject wrong = new FederationSubject(
                correct.playerId(), correct.localNetworkId(), correct.authenticatedSessionId(),
                correct.clientPublicKey(), correct.serverChallengeNonce(), correct.policyVersion(),
                correct.policySha256(), correct.authenticatedAt(),
                Optional.of(new FederationAuthenticationBinding(wrongHash)));
        FederationPresentation presentation = fixture.presentation(exchange.grant(), correct);

        assertEquals(FederationRuntimeStatus.INVALID_PRESENTATION,
                fixture.targetRuntime().receivePresentation(
                        wrong, fixture.outerPresentation(presentation, wrong), "target-console").status());
        assertTrue(fixture.targetRuntime().observations(fixture.playerId(), 10).isEmpty());

        assertEquals(FederationRuntimeStatus.OBSERVED,
                fixture.targetRuntime().receivePresentation(
                        correct, fixture.outerPresentation(presentation, correct), "target-console").status());
        assertEquals(1, fixture.targetRuntime().observations(fixture.playerId(), 10).size());
    }

    @Test
    void acceptanceDecisionUsesStrictVerifiedTimelineBoundaries() throws Exception {
        long issuedAt = NOW.toEpochMilli();
        long sourceAuthorizedAt = issuedAt + 1_000L;
        long verifiedAt = sourceAuthorizedAt + 1_000L;
        long expiresAt = verifiedAt + 1_000L;
        FederationVerification verification = new FederationVerification(
                SOURCE, TARGET, UUID.randomUUID().toString(), new byte[32],
                "source-session", UUID.randomUUID().toString(), new byte[32], issuedAt,
                sourceAuthorizedAt, expiresAt, verifiedAt, "policy-v1", new byte[32],
                FederationDocuments.MINIMAL_DISCLOSURE,
                FederationLocalClaim.FEDERATION_SOURCE_LOCALLY_VERIFIED);

        assertEquals(Instant.ofEpochMilli(expiresAt - 1L),
                FederationRuntime.strictAcceptanceInstant(verification, expiresAt - 1L));
        assertThrows(FederationException.class,
                () -> FederationRuntime.strictAcceptanceInstant(verification, expiresAt));
        assertThrows(FederationException.class,
                () -> FederationRuntime.strictAcceptanceInstant(verification, verifiedAt - 1L));
    }

    @Test
    void fullPresentationRejectsWhenDecisionSamplingReachesExactSignedExpiry() throws Exception {
        Fixture fixture = fixture();
        GrantExchange exchange = fixture.issueAndGrant();
        FederationPresentation presentation = fixture.presentation(
                exchange.grant(), fixture.targetSubject());
        List<FederationAuditRecord> audits = new ArrayList<>();
        long expiresAt = NOW.plus(Duration.ofMinutes(2)).toEpochMilli();
        FederationRuntime target = new FederationRuntime(
                fixture.clock(), new SecureRandom(), fixture.targetIdentity(),
                configuration(TARGET, SOURCE, fixture.sourceIdentity(),
                        FederationPeerCapability.ACCEPT_FROM),
                audits::add, FederationRuntime.DEFAULT_MAX_PENDING,
                FederationRuntime.DEFAULT_MAX_OBSERVATIONS,
                () -> System.nanoTime() / 1_000_000L, () -> expiresAt);

        FederationPresentationResult result = target.receivePresentation(
                fixture.targetSubject(),
                fixture.outerPresentation(presentation, fixture.targetSubject()),
                "target-console");

        assertEquals(FederationRuntimeStatus.INVALID_PRESENTATION, result.status());
        assertTrue(result.observation().isEmpty());
        assertTrue(target.observations(fixture.playerId(), 10).isEmpty());
        assertEquals(List.of(FederationAuditEvent.PRESENTATION_REJECTED),
                audits.stream().map(FederationAuditRecord::event).toList());
    }

    @Test
    void acceptanceLinearizesBeforeDurableAuditCompletesAcrossExpiry() throws Exception {
        Fixture fixture = fixture();
        GrantExchange exchange = fixture.issueAndGrant();
        FederationPresentation presentation = fixture.presentation(
                exchange.grant(), fixture.targetSubject());
        List<FederationAuditRecord> audits = new ArrayList<>();
        AtomicBoolean advanced = new AtomicBoolean();
        FederationRuntime target = new FederationRuntime(
                fixture.clock(), new SecureRandom(), fixture.targetIdentity(),
                configuration(TARGET, SOURCE, fixture.sourceIdentity(),
                        FederationPeerCapability.ACCEPT_FROM),
                record -> {
                    audits.add(record);
                    if (record.event() == FederationAuditEvent.PRESENTATION_ACCEPTED
                            && advanced.compareAndSet(false, true)) {
                        fixture.clock().advance(Duration.ofMinutes(2));
                    }
                });

        FederationPresentationResult result = target.receivePresentation(
                fixture.targetSubject(),
                fixture.outerPresentation(presentation, fixture.targetSubject()),
                "target-console");

        assertEquals(FederationRuntimeStatus.OBSERVED, result.status());
        assertEquals(NOW, result.observation().orElseThrow().observedAt());
        assertTrue(target.observations(fixture.playerId(), 10).isEmpty());
        assertEquals(List.of(FederationAuditEvent.PRESENTATION_ACCEPTED),
                audits.stream().map(FederationAuditRecord::event).toList());
        assertEquals(NOW, audits.getFirst().recordedAt());
    }

    @Test
    void rejectsWrongCapabilitiesAndConfigurationNetworkMismatch() throws Exception {
        Fixture fixture = fixture();
        FederationConfiguration wrongSourceDirection = configuration(
                SOURCE, TARGET, fixture.targetIdentity(), FederationPeerCapability.ACCEPT_FROM);
        FederationRuntime source = runtime(fixture.clock(), fixture.sourceIdentity(), wrongSourceDirection, new ArrayList<>());
        assertEquals(FederationRuntimeStatus.NOT_PINNED,
                source.issueConsent(fixture.sourceSubject(), TARGET, "source-console").status());

        GrantExchange exchange = fixture.issueAndGrant();
        FederationPresentation presentation = fixture.presentation(exchange.grant(), fixture.targetSubject());
        FederationConfiguration wrongTargetDirection = configuration(
                TARGET, SOURCE, fixture.sourceIdentity(), FederationPeerCapability.ISSUE_TO);
        FederationRuntime target = runtime(fixture.clock(), fixture.targetIdentity(), wrongTargetDirection, new ArrayList<>());
        assertEquals(FederationRuntimeStatus.NOT_PINNED,
                target.receivePresentation(fixture.targetSubject(),
                        fixture.outerPresentation(presentation, fixture.targetSubject()), "target-console").status());

        FederationSubject mismatchedNetwork = subject(
                fixture.playerId(), "other-target", "target-session", fixture.client(), fixture.targetChallenge());
        assertEquals(FederationRuntimeStatus.NO_CURRENT_SUBJECT,
                fixture.targetRuntime().receivePresentation(mismatchedNetwork,
                        fixture.outerPresentation(presentation, mismatchedNetwork), "target-console").status());
    }

    @Test
    void rejectsAReusedLocalAndPeerIdentityAtStartupAndReload() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        KeyPair localIdentity = Ed25519Keys.generate(new SecureRandom());
        FederationConfiguration sameKey = configuration(
                SOURCE, TARGET, localIdentity, FederationPeerCapability.ISSUE_TO);
        assertThrows(IllegalArgumentException.class, () ->
                runtime(clock, localIdentity, sameKey, new ArrayList<>()));

        KeyPair independentPeer = Ed25519Keys.generate(new SecureRandom());
        FederationRuntime runtime = runtime(
                clock, localIdentity,
                configuration(SOURCE, TARGET, independentPeer,
                        FederationPeerCapability.ISSUE_TO),
                new ArrayList<>());
        assertThrows(IllegalArgumentException.class, () -> runtime.reload(sameKey));
        assertTrue(MessageDigest.isEqual(
                FederationPeerPin.sha256(independentPeer.getPublic().getEncoded()),
                runtime.configuration().peers().get(TARGET).keyIdSha256()));
    }

    @Test
    void wrongPeerKeySessionChallengeAndAudienceAreInertAndDoNotConsumeValidInnerReplay() throws Exception {
        Fixture fixture = fixture();
        GrantExchange exchange = fixture.issueAndGrant();
        FederationPresentation valid = fixture.presentation(exchange.grant(), fixture.targetSubject());

        KeyPair wrongSource = Ed25519Keys.generate(new SecureRandom());
        FederationRuntime wrongPinRuntime = runtime(fixture.clock(), fixture.targetIdentity(),
                configuration(TARGET, SOURCE, wrongSource, FederationPeerCapability.ACCEPT_FROM), new ArrayList<>());
        assertEquals(FederationRuntimeStatus.INVALID_PRESENTATION,
                wrongPinRuntime.receivePresentation(fixture.targetSubject(),
                        fixture.outerPresentation(valid, fixture.targetSubject()), "target-console").status());

        FederationPresentation wrongSession = FederationDocuments.presentation(
                exchange.grant(), fixture.client().getPrivate(), "attacker-session",
                fixture.targetChallenge(), fixture.clock());
        assertEquals(FederationRuntimeStatus.INVALID_PRESENTATION,
                fixture.targetRuntime().receivePresentation(fixture.targetSubject(),
                        fixture.outerPresentation(wrongSession, fixture.targetSubject()), "target-console").status());

        byte[] wrongChallenge = fixture.targetChallenge();
        wrongChallenge[0] ^= 1;
        FederationPresentation wrongChallengePresentation = FederationDocuments.presentation(
                exchange.grant(), fixture.client().getPrivate(), fixture.targetSubject().authenticatedSessionId(),
                wrongChallenge, fixture.clock());
        assertEquals(FederationRuntimeStatus.INVALID_PRESENTATION,
                fixture.targetRuntime().receivePresentation(fixture.targetSubject(),
                        fixture.outerPresentation(wrongChallengePresentation, fixture.targetSubject()),
                        "target-console").status());

        // Invalid target bindings did not consume the assertion's one-time replay token.
        assertEquals(FederationRuntimeStatus.OBSERVED,
                fixture.targetRuntime().receivePresentation(fixture.targetSubject(),
                        fixture.outerPresentation(valid, fixture.targetSubject()), "target-console").status());

        // Keep the same pinned source key, client key, player, and target identity so the failure
        // is specifically the signed target audience rather than a coincidental key mismatch.
        var wrongAudienceRequest = FederationDocuments.issueConsentRequest(
                SOURCE, "other-target", fixture.playerId().toString(), fixture.client().getPublic(),
                fixture.sourceIdentity().getPublic(), fixture.targetIdentity().getPublic(),
                fixture.sourceSubject().authenticatedSessionId(), fixture.sourceSubject().policyVersion(),
                fixture.sourceSubject().policySha256(), fixture.clock(), Duration.ofMinutes(2),
                new SecureRandom());
        var wrongAudienceConsent = FederationDocuments.signClientConsent(
                wrongAudienceRequest, fixture.client().getPrivate(), fixture.client().getPublic(),
                fixture.clock(), ProtocolConstants.DEFAULT_CLOCK_SKEW);
        var wrongAudienceAssertion = FederationDocuments.signAssertion(
                wrongAudienceRequest, wrongAudienceConsent, fixture.client().getPublic(),
                fixture.sourceIdentity().getPrivate(), fixture.sourceIdentity().getPublic(),
                fixture.clock(), ProtocolConstants.DEFAULT_CLOCK_SKEW);
        FederationGrant wrongAudienceGrant = FederationDocuments.grant(
                wrongAudienceConsent, wrongAudienceAssertion, fixture.client().getPublic());
        FederationSubject wrongAudienceTarget = bind(fixture.targetSubject(), wrongAudienceGrant);
        FederationPresentation wrongAudience = fixture.presentation(
                wrongAudienceGrant, wrongAudienceTarget);
        assertEquals(FederationRuntimeStatus.INVALID_PRESENTATION,
                fixture.targetRuntime().receivePresentation(wrongAudienceTarget,
                        fixture.outerPresentation(wrongAudience, wrongAudienceTarget), "target-console").status());
        assertEquals(1, fixture.targetRuntime().observations(fixture.playerId(), 10).size());
    }

    @Test
    void requiresVaultKeyReuseAndRejectsInnerReplayEvenWithFreshOuterNonce() throws Exception {
        Fixture fixture = fixture();
        GrantExchange exchange = fixture.issueAndGrant();
        FederationPresentation presentation = fixture.presentation(exchange.grant(), fixture.targetSubject());
        byte[] firstOuter = fixture.outerPresentation(presentation, fixture.targetSubject());
        assertEquals(FederationRuntimeStatus.OBSERVED,
                fixture.targetRuntime().receivePresentation(
                        fixture.targetSubject(), firstOuter, "target-console").status());

        // Re-wrap the same inner presentation to ensure the independent assertion replay guard fires.
        byte[] freshOuter = fixture.outerPresentation(presentation, fixture.targetSubject());
        assertEquals(FederationRuntimeStatus.REPLAYED,
                fixture.targetRuntime().receivePresentation(
                        fixture.targetSubject(), freshOuter, "target-console").status());

        byte[] nextChallenge = randomBytes(new SecureRandom());
        FederationSubject nextTargetSession = bind(subject(
                fixture.playerId(), TARGET, "target-session-2", fixture.client(), nextChallenge),
                exchange.grant());
        FederationPresentation recapturedForNewSession = FederationDocuments.presentation(
                exchange.grant(), fixture.client().getPrivate(),
                nextTargetSession.authenticatedSessionId(), nextTargetSession.serverChallengeNonce(),
                fixture.clock());
        assertEquals(FederationRuntimeStatus.REPLAYED,
                fixture.targetRuntime().receivePresentation(nextTargetSession,
                        fixture.outerPresentation(recapturedForNewSession, nextTargetSession),
                        "target-console").status());
        assertEquals(1, fixture.targetRuntime().observations(fixture.playerId(), 10).size());

        KeyPair unrelatedTargetKey = Ed25519Keys.generate(new SecureRandom());
        FederationSubject targetWithDifferentSessionKey = bind(subject(
                fixture.playerId(), TARGET, "different-key-session", unrelatedTargetKey,
                fixture.targetChallenge()), exchange.grant());
        FederationPresentation proofWithSourceKey = FederationDocuments.presentation(
                exchange.grant(), fixture.client().getPrivate(),
                targetWithDifferentSessionKey.authenticatedSessionId(), targetWithDifferentSessionKey.serverChallengeNonce(),
                fixture.clock());
        assertEquals(FederationRuntimeStatus.INVALID_PRESENTATION,
                fixture.targetRuntime().receivePresentation(targetWithDifferentSessionKey,
                        outer(proofWithSourceKey, targetWithDifferentSessionKey, unrelatedTargetKey, fixture.clock()),
                        "target-console").status());
    }

    @Test
    void auditFailureFailsClosedAndDisconnectOrExpiryRemovesOnlyLocalState() throws Exception {
        Fixture fixture = fixture();
        FederationRuntime auditFailingSource = new FederationRuntime(
                fixture.clock(), new SecureRandom(), fixture.sourceIdentity(),
                configuration(SOURCE, TARGET, fixture.targetIdentity(), FederationPeerCapability.ISSUE_TO),
                ignored -> { throw new IllegalStateException("audit unavailable"); });
        assertEquals(FederationRuntimeStatus.AUDIT_FAILED,
                auditFailingSource.issueConsent(
                        fixture.sourceSubject(), TARGET, "source-console").status());
        assertEquals(0, auditFailingSource.status().pendingConsentRequests());
        assertTrue(auditFailingSource.status().configuredEnabled());
        assertFalse(auditFailingSource.status().enabled());
        assertFalse(auditFailingSource.status().auditHealthy());
        assertTrue(auditFailingSource.status().auditFailures() >= 1L);

        CountDownLatch auditWorkerEntered = new CountDownLatch(1);
        CountDownLatch releaseAuditWorker = new CountDownLatch(1);
        try (BoundedAsyncFederationAuditSink saturatedAudit = new BoundedAsyncFederationAuditSink(
                ignored -> {
                    auditWorkerEntered.countDown();
                    try {
                        if (!releaseAuditWorker.await(5, TimeUnit.SECONDS)) {
                            throw new IllegalStateException("audit test worker timeout");
                        }
                    } catch (InterruptedException exception) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException("audit test worker interrupted", exception);
                    }
                }, 1, "mcace-federation-runtime-audit-test")) {
            assertTrue(saturatedAudit.offer(auditRecord()));
            assertTrue(auditWorkerEntered.await(5, TimeUnit.SECONDS));
            assertTrue(saturatedAudit.offer(auditRecord()));
            FederationRuntime saturatedSource = new FederationRuntime(
                    fixture.clock(), new SecureRandom(), fixture.sourceIdentity(),
                    configuration(SOURCE, TARGET, fixture.targetIdentity(), FederationPeerCapability.ISSUE_TO),
                    saturatedAudit);
            assertEquals(FederationRuntimeStatus.AUDIT_FAILED,
                    saturatedSource.issueConsent(
                            fixture.sourceSubject(), TARGET, "source-console").status());
            assertEquals(0, saturatedSource.status().pendingConsentRequests());
            assertFalse(saturatedSource.status().enabled());
            assertFalse(saturatedSource.status().auditHealthy());
            assertEquals(1L, saturatedAudit.status().saturated());
            releaseAuditWorker.countDown();
        }

        CountDownLatch backgroundFailureEntered = new CountDownLatch(1);
        try (BoundedAsyncFederationAuditSink backgroundFailingAudit =
                     new BoundedAsyncFederationAuditSink(ignored -> {
                         backgroundFailureEntered.countDown();
                         throw new IllegalStateException("injected background disk failure");
                     }, 4, "mcace-federation-runtime-background-failure-test")) {
            FederationRuntime backgroundFailingSource = new FederationRuntime(
                    fixture.clock(), new SecureRandom(), fixture.sourceIdentity(),
                    configuration(SOURCE, TARGET, fixture.targetIdentity(), FederationPeerCapability.ISSUE_TO),
                    backgroundFailingAudit);
            assertTrue(backgroundFailingAudit.offer(auditRecord()));
            assertTrue(backgroundFailureEntered.await(5, TimeUnit.SECONDS));
            awaitAuditFault(backgroundFailingAudit);

            assertEquals(FederationRuntimeStatus.AUDIT_FAILED,
                    backgroundFailingSource.issueConsent(
                            fixture.sourceSubject(), TARGET, "source-console").status());
            FederationRuntimeState failed = backgroundFailingSource.status();
            assertTrue(failed.configuredEnabled());
            assertFalse(failed.enabled());
            assertFalse(failed.auditHealthy());
            assertEquals(0, failed.pendingConsentRequests());
            assertEquals(0, failed.activeObservations());
        }

        GrantExchange exchange = fixture.issueAndGrant();
        FederationPresentation presentation = fixture.presentation(exchange.grant(), fixture.targetSubject());

        FederationRuntime auditFailingTarget = new FederationRuntime(
                fixture.clock(), new SecureRandom(), fixture.targetIdentity(),
                configuration(TARGET, SOURCE, fixture.sourceIdentity(), FederationPeerCapability.ACCEPT_FROM),
                ignored -> { throw new IllegalStateException("audit unavailable"); });
        assertEquals(FederationRuntimeStatus.AUDIT_FAILED,
                auditFailingTarget.receivePresentation(fixture.targetSubject(),
                        fixture.outerPresentation(presentation, fixture.targetSubject()), "target-console").status());
        assertTrue(auditFailingTarget.observations(fixture.playerId(), 10).isEmpty());

        assertEquals(FederationRuntimeStatus.OBSERVED,
                fixture.targetRuntime().receivePresentation(fixture.targetSubject(),
                        fixture.outerPresentation(presentation, fixture.targetSubject()), "target-console").status());
        fixture.targetRuntime().removeForSession(
                fixture.playerId(), fixture.targetSubject().authenticatedSessionId());
        assertTrue(fixture.targetRuntime().observations(fixture.playerId(), 10).isEmpty());

        FederationIssueResult pending = fixture.sourceRuntime().issueConsent(
                fixture.sourceSubject(), TARGET, "source-console");
        assertEquals(FederationRuntimeStatus.CONSENT_ISSUED, pending.status());
        fixture.sourceRuntime().removeForPlayer(fixture.playerId());
        assertEquals(0, fixture.sourceRuntime().status().pendingConsentRequests());

        Fixture expiring = fixture();
        GrantExchange expiringGrant = expiring.issueAndGrant();
        FederationPresentation expiringPresentation = expiring.presentation(
                expiringGrant.grant(), expiring.targetSubject());
        assertEquals(FederationRuntimeStatus.OBSERVED,
                expiring.targetRuntime().receivePresentation(expiring.targetSubject(),
                        expiring.outerPresentation(expiringPresentation, expiring.targetSubject()),
                        "target-console").status());
        expiring.clock().advance(Duration.ofMinutes(3));
        expiring.targetRuntime().expire(100);
        assertTrue(expiring.targetRuntime().observations(expiring.playerId(), 10).isEmpty());
    }

    @Test
    void backgroundAuditFailureDisablesRuntimeAndClearsPreviouslyCommittedEphemeralState() throws Exception {
        Fixture fixture = fixture();
        java.util.concurrent.atomic.AtomicInteger sourceWrites = new java.util.concurrent.atomic.AtomicInteger();
        try (BoundedAsyncFederationAuditSink audit = new BoundedAsyncFederationAuditSink(record -> {
            if (sourceWrites.incrementAndGet() > 1) {
                throw new IllegalStateException("injected post-commit source audit failure");
            }
        }, 4, "mcace-federation-source-fault-after-commit")) {
            FederationRuntime source = new FederationRuntime(
                    fixture.clock(), new SecureRandom(), fixture.sourceIdentity(),
                    configuration(SOURCE, TARGET, fixture.targetIdentity(), FederationPeerCapability.ISSUE_TO),
                    audit);
            assertEquals(FederationRuntimeStatus.CONSENT_ISSUED,
                    source.issueConsent(fixture.sourceSubject(), TARGET, "source-console").status());
            assertEquals(1, source.status().pendingConsentRequests());

            assertTrue(audit.offer(auditRecord()));
            awaitAuditFault(audit);
            assertEquals(0, source.expire(100));
            FederationRuntimeState failed = source.status();
            assertFalse(failed.enabled());
            assertFalse(failed.auditHealthy());
            assertEquals(0, failed.pendingConsentRequests());
            assertEquals(FederationRuntimeStatus.AUDIT_FAILED,
                    source.issueConsent(fixture.sourceSubject(), TARGET, "source-console").status());
        }

        GrantExchange exchange = fixture.issueAndGrant();
        FederationPresentation presentation = fixture.presentation(exchange.grant(), fixture.targetSubject());
        java.util.concurrent.atomic.AtomicInteger targetWrites = new java.util.concurrent.atomic.AtomicInteger();
        try (BoundedAsyncFederationAuditSink audit = new BoundedAsyncFederationAuditSink(record -> {
            if (targetWrites.incrementAndGet() > 1) {
                throw new IllegalStateException("injected post-commit target audit failure");
            }
        }, 4, "mcace-federation-target-fault-after-commit")) {
            FederationRuntime target = new FederationRuntime(
                    fixture.clock(), new SecureRandom(), fixture.targetIdentity(),
                    configuration(TARGET, SOURCE, fixture.sourceIdentity(), FederationPeerCapability.ACCEPT_FROM),
                    audit);
            assertEquals(FederationRuntimeStatus.OBSERVED,
                    target.receivePresentation(fixture.targetSubject(),
                            fixture.outerPresentation(presentation, fixture.targetSubject()),
                            "target-console").status());
            assertEquals(1, target.status().activeObservations());

            assertTrue(audit.offer(auditRecord()));
            awaitAuditFault(audit);
            assertEquals(0, target.expire(100));
            FederationRuntimeState failed = target.status();
            assertFalse(failed.enabled());
            assertFalse(failed.auditHealthy());
            assertEquals(0, failed.activeObservations());
            assertTrue(target.observations(fixture.playerId(), 10).isEmpty());
        }
    }

    @Test
    void wallClockRollbackTripsStickyFailClosedStateAndClearsPendingState() throws Exception {
        Fixture fixture = fixture();
        AtomicLong monotonicMillis = new AtomicLong(1_000L);
        FederationRuntime source = new FederationRuntime(
                fixture.clock(), new SecureRandom(), fixture.sourceIdentity(),
                configuration(SOURCE, TARGET, fixture.targetIdentity(),
                        FederationPeerCapability.ISSUE_TO),
                ignored -> { }, FederationRuntime.DEFAULT_MAX_PENDING,
                FederationRuntime.DEFAULT_MAX_OBSERVATIONS, monotonicMillis::get);

        assertEquals(FederationRuntimeStatus.CONSENT_ISSUED,
                source.issueConsent(fixture.sourceSubject(), TARGET, "source-console").status());
        assertEquals(1, source.status().pendingConsentRequests());

        fixture.clock().advance(Duration.ofSeconds(60));
        monotonicMillis.addAndGet(Duration.ofSeconds(60).toMillis());
        assertTrue(source.status().enabled());
        assertEquals(1, source.status().pendingConsentRequests());

        fixture.clock().advance(Duration.ofSeconds(-45));
        monotonicMillis.addAndGet(Duration.ofSeconds(1).toMillis());
        FederationRuntimeState faulted = source.status();
        assertFalse(faulted.enabled());
        assertTrue(faulted.configuredEnabled());
        assertEquals(0, faulted.pendingConsentRequests());
        assertEquals(0, faulted.activeObservations());

        fixture.clock().advance(Duration.ofMinutes(10));
        monotonicMillis.addAndGet(Duration.ofMinutes(10).toMillis());
        assertEquals(FederationRuntimeStatus.DISABLED,
                source.issueConsent(fixture.sourceSubject(), TARGET, "source-console").status());
        assertFalse(source.status().enabled());
    }

    @Test
    void classifierRoutesOnlyBoundedFederationDirections() throws Exception {
        Fixture fixture = fixture();
        GrantExchange exchange = fixture.issueAndGrant();
        FederationPresentation presentation = fixture.presentation(exchange.grant(), fixture.targetSubject());
        assertEquals(FederationFrameKind.CLIENT_PRESENTATION,
                FederationFrameClassifier.classify(
                        fixture.outerPresentation(presentation, fixture.targetSubject())));
        assertEquals(FederationFrameKind.SERVER_ONLY,
                FederationFrameClassifier.classify(exchange.issue().outboundFrame().orElseThrow()));
        assertEquals(FederationFrameKind.MALFORMED,
                FederationFrameClassifier.classify(
                        new byte[ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES + 1]));
        assertEquals(FederationFrameKind.MALFORMED,
                FederationFrameClassifier.classify(new byte[] {1, 2, 3}));
    }

    private static Fixture fixture() throws Exception {
        return fixture(TARGET);
    }

    private static Fixture fixture(String targetNetworkId) throws Exception {
        MutableClock clock = new MutableClock(NOW);
        SecureRandom random = new SecureRandom();
        KeyPair client = Ed25519Keys.generate(random);
        KeyPair sourceIdentity = Ed25519Keys.generate(random);
        KeyPair targetIdentity = Ed25519Keys.generate(random);
        UUID playerId = UUID.randomUUID();
        byte[] sourceChallenge = randomBytes(random);
        byte[] targetChallenge = randomBytes(random);
        FederationSubject sourceSubject = subject(
                playerId, SOURCE, "source-session", client, sourceChallenge);
        FederationSubject targetSubject = subject(
                playerId, targetNetworkId, "target-session", client, targetChallenge);
        AtomicReference<FederationAuthenticationBinding> targetAuthBinding = new AtomicReference<>();
        List<FederationAuditRecord> sourceAudits = new ArrayList<>();
        List<FederationAuditRecord> targetAudits = new ArrayList<>();
        FederationRuntime sourceRuntime = runtime(clock, sourceIdentity,
                configuration(SOURCE, targetNetworkId, targetIdentity, FederationPeerCapability.ISSUE_TO),
                sourceAudits);
        FederationRuntime targetRuntime = runtime(clock, targetIdentity,
                configuration(targetNetworkId, SOURCE, sourceIdentity, FederationPeerCapability.ACCEPT_FROM),
                targetAudits);
        return new Fixture(clock, client, sourceIdentity, targetIdentity, playerId,
                sourceChallenge, targetChallenge, sourceSubject, targetSubject, targetAuthBinding,
                sourceRuntime, targetRuntime, sourceAudits, targetAudits);
    }

    private static FederationRuntime runtime(
            MutableClock clock,
            KeyPair identity,
            FederationConfiguration configuration,
            List<FederationAuditRecord> audit) {
        return new FederationRuntime(clock, new SecureRandom(), identity, configuration, audit::add);
    }

    private static FederationConfiguration configuration(
            String local,
            String peerId,
            KeyPair peerIdentity,
            FederationPeerCapability capability) {
        FederationPeerPin pin = new FederationPeerPin(
                peerId, peerIdentity.getPublic(),
                FederationPeerPin.sha256(peerIdentity.getPublic().getEncoded()), Set.of(capability));
        return new FederationConfiguration(true, local, Duration.ofMinutes(2), Map.of(peerId, pin));
    }

    private static FederationSubject subject(
            UUID playerId,
            String localNetworkId,
            String sessionId,
            KeyPair client,
            byte[] challenge) throws Exception {
        return new FederationSubject(playerId, localNetworkId, sessionId, client.getPublic(), challenge,
                "policy-v1", MessageDigest.getInstance("SHA-256").digest("policy".getBytes()), NOW);
    }

    private static FederationSubject bind(FederationSubject subject, FederationGrant grant)
            throws Exception {
        return new FederationSubject(
                subject.playerId(), subject.localNetworkId(), subject.authenticatedSessionId(),
                subject.clientPublicKey(), subject.serverChallengeNonce(), subject.policyVersion(),
                subject.policySha256(), subject.authenticatedAt(),
                Optional.of(new FederationAuthenticationBinding(
                        FederationDocuments.signedAssertionSha256(grant))));
    }

    private static byte[] randomBytes(SecureRandom random) {
        byte[] result = new byte[ProtocolConstants.NONCE_BYTES];
        random.nextBytes(result);
        return result;
    }

    private static FederationAuditRecord auditRecord() {
        return new FederationAuditRecord(
                NOW, FederationAuditEvent.PRESENTATION_REJECTED,
                FederationAuditOutcome.INVALID_PRESENTATION, "test-operator", UUID.randomUUID(),
                SOURCE, TARGET, java.util.Optional.empty(), java.util.Optional.empty());
    }

    private static void awaitAuditFault(BoundedAsyncFederationAuditSink sink) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            if (!sink.health().available()) {
                return;
            }
            Thread.sleep(10L);
        }
        assertFalse(sink.health().available());
    }

    private static byte[] outer(
            FederationPresentation presentation,
            FederationSubject targetSubject,
            KeyPair signingKey,
            Clock clock) throws Exception {
        EnvelopeCodec codec = new EnvelopeCodec(clock, new SecureRandom(),
                ProtocolConstants.MAX_FEDERATION_PRESENTATION_BYTES,
                ProtocolConstants.DEFAULT_CLOCK_SKEW);
        return codec.sign(PacketType.FEDERATION_PRESENTATION,
                targetSubject.authenticatedSessionId(), FederationDocuments.encode(presentation),
                signingKey.getPrivate()).toByteArray();
    }

    private record GrantExchange(FederationIssueResult issue, FederationGrant grant) { }

    private record Fixture(
            MutableClock clock,
            KeyPair client,
            KeyPair sourceIdentity,
            KeyPair targetIdentity,
            UUID playerId,
            byte[] sourceChallenge,
            byte[] targetChallenge,
            FederationSubject sourceSubject,
            FederationSubject baseTargetSubject,
            AtomicReference<FederationAuthenticationBinding> targetAuthBinding,
            FederationRuntime sourceRuntime,
            FederationRuntime targetRuntime,
            List<FederationAuditRecord> sourceAudits,
            List<FederationAuditRecord> targetAudits) {
        private Fixture {
            sourceChallenge = sourceChallenge.clone();
            targetChallenge = targetChallenge.clone();
        }

        @Override public byte[] sourceChallenge() { return sourceChallenge.clone(); }
        @Override public byte[] targetChallenge() { return targetChallenge.clone(); }

        private FederationSubject targetSubject() {
            FederationAuthenticationBinding binding = targetAuthBinding.get();
            return new FederationSubject(
                    baseTargetSubject.playerId(), baseTargetSubject.localNetworkId(),
                    baseTargetSubject.authenticatedSessionId(), baseTargetSubject.clientPublicKey(),
                    baseTargetSubject.serverChallengeNonce(), baseTargetSubject.policyVersion(),
                    baseTargetSubject.policySha256(), baseTargetSubject.authenticatedAt(),
                    Optional.ofNullable(binding));
        }

        private GrantExchange issueAndGrant() throws Exception {
            FederationIssueResult issue = sourceRuntime.issueConsent(
                    sourceSubject, baseTargetSubject.localNetworkId(), "source-console");
            assertEquals(FederationRuntimeStatus.CONSENT_ISSUED, issue.status());
            var request = issue.request().orElseThrow();
            var consent = FederationDocuments.signClientConsent(
                    request, client.getPrivate(), client.getPublic(), clock,
                    ProtocolConstants.DEFAULT_CLOCK_SKEW);
            EnvelopeCodec clientCodec = new EnvelopeCodec(clock, new SecureRandom(),
                    ProtocolConstants.MAX_FEDERATION_PRESENTATION_BYTES,
                    ProtocolConstants.DEFAULT_CLOCK_SKEW);
            byte[] responseFrame = clientCodec.sign(
                    PacketType.FEDERATION_CONSENT_RESPONSE, sourceSubject.authenticatedSessionId(),
                    FederationDocuments.encodeConsentResponse(consent), client.getPrivate()).toByteArray();
            FederationGrantResult result = sourceRuntime.receiveConsentResponse(sourceSubject, responseFrame);
            assertEquals(FederationRuntimeStatus.GRANT_READY, result.status());
            FederationGrant grant = result.grant().orElseThrow();
            targetAuthBinding.set(new FederationAuthenticationBinding(
                    FederationDocuments.signedAssertionSha256(grant)));
            assertEquals(grant, FederationDocuments.verifyGrant(
                    FederationDocuments.encodeGrant(grant), request, client.getPublic(),
                    sourceIdentity.getPublic(), clock, ProtocolConstants.DEFAULT_CLOCK_SKEW));
            return new GrantExchange(issue, grant);
        }

        private FederationPresentation presentation(
                FederationGrant grant,
                FederationSubject target) throws Exception {
            return FederationDocuments.presentation(grant, client.getPrivate(),
                    target.authenticatedSessionId(), target.serverChallengeNonce(), clock);
        }

        private byte[] outerPresentation(
                FederationPresentation presentation,
                FederationSubject target) throws Exception {
            return outer(presentation, target, client, clock);
        }
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        private MutableClock(Instant now) {
            this.now = now;
        }

        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
        private void advance(Duration duration) { now = now.plus(duration); }
    }
}
