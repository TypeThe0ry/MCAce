package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class ServerBehaviorCorrelationRuntimeTest {
    private static final Instant NOW = Instant.parse("2026-08-22T00:00:00Z");
    private static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final String HASH = "00".repeat(32);

    @Test
    void providerCorrelationCreatesDurablyAuthorizedHighImpactEvent() throws Exception {
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        SignedDispositionPolicyDocument signed = signed(identity);
        ArrayList<TrustedDispositionAuthorizationRecord> records = new ArrayList<>();
        SharedProxyDispositionPolicyRuntime policy = new SharedProxyDispositionPolicyRuntime(
                ProxyFamily.VELOCITY, () -> signed, identity.getPublic(),
                Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofSeconds(30));
        ServerBehaviorCorrelationRuntime runtime = new ServerBehaviorCorrelationRuntime(
                policy, records::add, Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofSeconds(30),
                Set.of("grim"));
        ServerBehaviorObservation provider = new ServerBehaviorObservation(
                PLAYER, "session-a", "grim", "Simulation", NOW.minusSeconds(2));

        ServerBehaviorCorrelationResult result = runtime.correlate(
                PLAYER, "session-a", context(), NOW.minusSeconds(3), clientObservation(), provider)
                .orElseThrow();

        assertEquals(DispositionAction.QUARANTINE, result.evaluation().decision().action());
        assertTrue(result.authorizedEvent().isPresent());
        assertEquals(ObservationOrigin.SERVER_CONFIRMED,
                result.authorizedEvent().orElseThrow().authorityOrigin());
        assertEquals(1, records.size());
    }

    @Test
    void untrustedProviderAndClientOnlySignalNeverReachAuthorization() throws Exception {
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        SignedDispositionPolicyDocument signed = signed(identity);
        SharedProxyDispositionPolicyRuntime policy = new SharedProxyDispositionPolicyRuntime(
                ProxyFamily.VELOCITY, () -> signed, identity.getPublic(),
                Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofSeconds(30));
        ArrayList<TrustedDispositionAuthorizationRecord> records = new ArrayList<>();
        ServerBehaviorCorrelationRuntime runtime = new ServerBehaviorCorrelationRuntime(
                policy, records::add, Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofSeconds(30),
                Set.of("grim"));
        ServerBehaviorObservation untrusted = new ServerBehaviorObservation(
                PLAYER, "session-a", "unknown-provider", "Simulation", NOW.minusSeconds(2));

        assertTrue(runtime.correlate(PLAYER, "session-a", context(), NOW.minusSeconds(3),
                clientObservation(), untrusted).isEmpty());
        assertTrue(records.isEmpty());
    }

    private static ArtifactObservation clientObservation() {
        return new ArtifactObservation(ArtifactType.MOD, "example-cheat", "1.0.0", HASH,
                Map.of("scope", "mods"), ObservationOrigin.CLIENT_REPORTED, Confidence.LOW, false);
    }

    private static EvaluationContext context() {
        return new EvaluationContext(PLAYER, "velocity", "lobby", null, null, Set.of(), NOW);
    }

    private static SignedDispositionPolicyDocument signed(KeyPair identity) throws Exception {
        DetectionRule rule = DetectionRule.newBuilder()
                .setRuleId("server-confirmed-exact")
                .setRevision(1)
                .setPriority(100)
                .setSelector(DetectionSelector.newBuilder()
                        .setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_EXACT_SHA256)
                        .setSha256(ByteString.copyFrom(new byte[32])))
                .setConfidence(DetectionConfidence.DETECTION_CONFIDENCE_CONFIRMED)
                .setDefaultAction(com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_QUARANTINE)
                .setIntroducedAtEpochMs(NOW.toEpochMilli() - 1_000)
                .setEffectiveFromEpochMs(NOW.toEpochMilli() - 1_000)
                .setExpiresAtEpochMs(NOW.toEpochMilli() + 86_400_000)
                .build();
        DispositionPolicyDocument document = DispositionPolicyDocument.newBuilder()
                .setSchemaVersion(1).setPolicyId("server-correlation")
                .setVersion("server-correlation-1").setSequence(1)
                .setIssuedAtEpochMs(NOW.toEpochMilli() - 1_000)
                .setEffectiveFromEpochMs(NOW.toEpochMilli() - 1_000)
                .setExpiresAtEpochMs(NOW.toEpochMilli() + 86_400_000)
                .setRolloutStage("FULL")
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(identity.getPublic())))
                .addRules(rule).build();
        return DispositionPolicyDocuments.sign(document, identity.getPrivate(), identity.getPublic());
    }
}
