package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

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
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

final class SharedProxyDispositionPolicyRuntimeTest {
    private static final long NOW = 1_786_118_400_000L;
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC);
    private KeyPair identity;

    @BeforeEach
    void setUp() throws Exception {
        identity = Ed25519Keys.generate(new SecureRandom());
    }

    @Test
    void velocityAndBungeeCordUseTheSameVerifiedEvaluationPath() throws Exception {
        SignedDispositionPolicyDocument signed = signed(policy(1, null,
                com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_WARN, NOW - 1_000, NOW + 86_400_000));
        AtomicReference<SignedDispositionPolicyDocument> source = new AtomicReference<>(signed);

        ProxyPolicyEvaluation velocity = runtime(ProxyFamily.VELOCITY, source).evaluate(context(), observation());
        ProxyPolicyEvaluation bungee = runtime(ProxyFamily.BUNGEECORD, source).evaluate(context(), observation());

        assertEquals(DispositionAction.WARN, velocity.decision().action());
        assertEquals(velocity.decision(), bungee.decision());
        assertEquals(velocity.activePolicyVersion(), bungee.activePolicyVersion());
        assertEquals(velocity.activePolicySequence(), bungee.activePolicySequence());
        assertEquals(ProxyPolicyRefreshStatus.ACTIVE, velocity.refreshStatus());
        assertEquals(ProxyFamily.BUNGEECORD, bungee.proxyFamily());
    }

    @Test
    void expiredAndBadlySignedPoliciesFailToTheExplicitObserveDefault() throws Exception {
        AtomicReference<SignedDispositionPolicyDocument> expired = new AtomicReference<>(signed(policy(
                1, null, com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_WARN,
                NOW - Duration.ofDays(2).toMillis(), NOW - Duration.ofMinutes(1).toMillis())));
        ProxyPolicyEvaluation expiredEvaluation = runtime(ProxyFamily.VELOCITY, expired).evaluate(context(), observation());

        assertEquals(DispositionAction.OBSERVE, expiredEvaluation.decision().action());
        assertEquals(ProxyPolicyRefreshStatus.OBSERVE_NO_VALID_POLICY, expiredEvaluation.refreshStatus());
        assertFalse(expiredEvaluation.activePolicySequence().isPresent());

        SignedDispositionPolicyDocument valid = signed(policy(1, null,
                com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_WARN, NOW - 1_000, NOW + 86_400_000));
        AtomicReference<SignedDispositionPolicyDocument> tampered = new AtomicReference<>(valid.toBuilder()
                .setSignature(ByteString.copyFrom(new byte[64]))
                .build());
        ProxyPolicyEvaluation tamperedEvaluation = runtime(ProxyFamily.BUNGEECORD, tampered).evaluate(context(), observation());

        assertEquals(DispositionAction.OBSERVE, tamperedEvaluation.decision().action());
        assertEquals(ProxyPolicyRefreshStatus.OBSERVE_NO_VALID_POLICY, tamperedEvaluation.refreshStatus());
        assertFalse(tamperedEvaluation.activePolicySequence().isPresent());
    }

    @Test
    void brokenPolicySourcesCannotEscapeTheObserveBoundary() {
        SharedProxyDispositionPolicyRuntime nullSource = new SharedProxyDispositionPolicyRuntime(
                ProxyFamily.VELOCITY, () -> null, identity.getPublic(), CLOCK, Duration.ofSeconds(30));
        SharedProxyDispositionPolicyRuntime throwingSource = new SharedProxyDispositionPolicyRuntime(
                ProxyFamily.BUNGEECORD,
                () -> { throw new IllegalStateException("backend policy store is unavailable"); },
                identity.getPublic(), CLOCK, Duration.ofSeconds(30));

        assertEquals(DispositionAction.OBSERVE,
                nullSource.evaluate(context(), observation()).decision().action());
        assertEquals(ProxyPolicyRefreshStatus.OBSERVE_NO_VALID_POLICY,
                nullSource.evaluate(context(), observation()).refreshStatus());
        assertEquals(DispositionAction.OBSERVE,
                throwingSource.evaluate(context(), observation()).decision().action());
        assertEquals(ProxyPolicyRefreshStatus.OBSERVE_NO_VALID_POLICY,
                throwingSource.evaluate(context(), observation()).refreshStatus());
    }

    @Test
    void rollbackCannotReplaceTheLastKnownGoodChainedPolicy() throws Exception {
        DispositionPolicyDocument first = policy(1, null,
                com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_WARN, NOW - 1_000, NOW + 86_400_000);
        DispositionPolicyDocument second = policy(2, DispositionPolicyDocuments.documentSha256(first),
                com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_LIMIT, NOW - 1_000, NOW + 86_400_000);
        AtomicReference<SignedDispositionPolicyDocument> source = new AtomicReference<>(signed(first));
        SharedProxyDispositionPolicyRuntime runtime = runtime(ProxyFamily.VELOCITY, source);

        assertEquals(DispositionAction.WARN, runtime.evaluate(context(), observation()).decision().action());
        source.set(signed(second));
        assertEquals(DispositionAction.LIMIT, runtime.evaluate(context(), observation()).decision().action());
        source.set(signed(first));
        ProxyPolicyEvaluation replay = runtime.evaluate(context(), observation());

        assertEquals(ProxyPolicyRefreshStatus.REJECTED_ROLLBACK, replay.refreshStatus());
        assertEquals(DispositionAction.LIMIT, replay.decision().action());
        assertEquals(2L, replay.activePolicySequence().orElseThrow());
    }

    private SharedProxyDispositionPolicyRuntime runtime(
            ProxyFamily family, AtomicReference<SignedDispositionPolicyDocument> source) {
        return new SharedProxyDispositionPolicyRuntime(
                family, source::get, identity.getPublic(), CLOCK, Duration.ofSeconds(30));
    }

    private SignedDispositionPolicyDocument signed(DispositionPolicyDocument document) throws Exception {
        return DispositionPolicyDocuments.sign(document, identity.getPrivate(), identity.getPublic());
    }

    private DispositionPolicyDocument policy(
            long sequence,
            byte[] predecessor,
            com.ellan.mcace.protocol.generated.DispositionAction action,
            long issuedAt,
            long expiresAt) throws Exception {
        return DispositionPolicyDocument.newBuilder()
                .setSchemaVersion(1)
                .setPolicyId("network-default")
                .setVersion("2026.08.08-" + sequence)
                .setSequence(sequence)
                .setIssuedAtEpochMs(issuedAt)
                .setEffectiveFromEpochMs(issuedAt)
                .setExpiresAtEpochMs(expiresAt)
                .setRolloutStage("OBSERVE")
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(identity.getPublic())))
                .setPreviousDocumentSha256(predecessor == null ? ByteString.EMPTY : ByteString.copyFrom(predecessor))
                .addRules(rule(action, issuedAt, expiresAt))
                .build();
    }

    private static DetectionRule rule(
            com.ellan.mcace.protocol.generated.DispositionAction action, long effectiveFrom, long expiresAt) {
        return DetectionRule.newBuilder()
                .setRuleId("example-mod")
                .setRevision(1)
                .setPriority(100)
                .setSelector(DetectionSelector.newBuilder()
                        .setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_EXACT_SHA256)
                        .setSha256(ByteString.copyFrom(new byte[32])))
                .setConfidence(DetectionConfidence.DETECTION_CONFIDENCE_HIGH)
                .setDefaultAction(action)
                .setIntroducedAtEpochMs(effectiveFrom)
                .setEffectiveFromEpochMs(effectiveFrom)
                .setExpiresAtEpochMs(expiresAt)
                .build();
    }

    private static EvaluationContext context() {
        return new EvaluationContext(
                UUID.fromString("00000000-0000-0000-0000-000000000001"),
                "proxy-a", "survival", "world", "normal", Set.of("member"), Instant.ofEpochMilli(NOW));
    }

    private static ArtifactObservation observation() {
        return new ArtifactObservation(
                ArtifactType.MOD, "example.mod", "1.0.0", "00".repeat(32), Map.of(),
                ObservationOrigin.CLIENT_REPORTED, Confidence.HIGH, false);
    }
}
