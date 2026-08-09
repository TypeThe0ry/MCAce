package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.ArtifactType;
import com.ellan.mcace.core.disposition.Confidence;
import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.DispositionPolicyConfigurationCompiler;
import com.ellan.mcace.core.disposition.EvaluationContext;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import com.ellan.mcace.core.session.AuthenticatedManifest;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.AuthRequest;
import com.ellan.mcace.protocol.generated.DetectionArtifactType;
import com.ellan.mcace.protocol.generated.DetectionCatalogCategory;
import com.ellan.mcace.protocol.generated.DetectionConfidence;
import com.ellan.mcace.protocol.generated.DetectionMatchType;
import com.ellan.mcace.protocol.generated.DetectionRule;
import com.ellan.mcace.protocol.generated.DetectionSelector;
import com.ellan.mcace.protocol.generated.DetectionCatalogEntry;
import com.ellan.mcace.protocol.generated.DetectionCatalogSelection;
import com.ellan.mcace.protocol.generated.DispositionPolicyConfiguration;
import com.ellan.mcace.protocol.generated.DispositionPolicyDocument;
import com.ellan.mcace.protocol.generated.FileEntry;
import com.ellan.mcace.protocol.generated.IntegrityScopeManifest;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
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
import java.util.HexFormat;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class AuthenticatedManifestContentRootRuntimeTest {
    private static final long NOW = 1_786_118_400_000L;
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC);

    @Test
    void signedCatalogContentRootHitsWarnAndQuarantineForDerivedDirectoryPackage() throws Exception {
        ArtifactObservation packageObservation = derivePackage();
        String root = packageObservation.metadata().get("content_root_sha256");
        KeyPair keyPair = Ed25519Keys.generate(new SecureRandom());

        ProxyPolicyEvaluation warn = runtime(keyPair, root,
                com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_WARN)
                .evaluate(context(), packageObservation);
        ProxyPolicyEvaluation quarantine = runtime(keyPair, root,
                com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_QUARANTINE)
                .evaluate(context(), packageObservation);

        assertEquals(ArtifactType.RESOURCE_PACK, packageObservation.type());
        assertEquals(ObservationOrigin.CLIENT_REPORTED, packageObservation.origin());
        assertEquals(Confidence.LOW, packageObservation.confidence());
        assertEquals(DispositionAction.WARN, warn.decision().action());
        assertEquals(DispositionAction.QUARANTINE, quarantine.decision().action());
    }

    @Test
    void topLevelZipUsesExistingExactHashObservationWithoutDirectoryRoot() throws Exception {
        byte[] hash = new byte[32]; hash[0] = 9;
        AuthRequest request = AuthRequest.newBuilder().addScopeManifests(
                IntegrityScopeManifest.newBuilder().setScope("resourcepacks").setPresent(true)
                        .addEntries(file("pack.zip", 10, hash))).build();
        AuthenticatedManifest manifest = new AuthenticatedManifest(
                UUID.fromString("00000000-0000-0000-0000-000000000001"), "session-123456789012",
                SecurityPolicy.getDefaultInstance(), request, Instant.ofEpochMilli(NOW));
        ArtifactObservation observation = new AuthenticatedManifestObservationDeriver().derive(manifest)
                .observations().getFirst();
        KeyPair keyPair = Ed25519Keys.generate(new SecureRandom());
        String hashHex = HexFormat.of().formatHex(hash);
        SignedDispositionPolicyDocument signed = signedCatalog(keyPair,
                DetectionMatchType.DETECTION_MATCH_EXACT_SHA256, hashHex,
                com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_WARN);

        ProxyPolicyEvaluation evaluation = new SharedProxyDispositionPolicyRuntime(
                ProxyFamily.VELOCITY,
                () -> signed,
                keyPair.getPublic(), CLOCK, Duration.ofSeconds(30))
                .evaluate(context(), observation);

        assertEquals(DispositionAction.WARN, evaluation.decision().action());
        assertEquals(hashHex, observation.sha256());
        assertNull(observation.metadata().get("package_kind"));
    }

    private static ArtifactObservation derivePackage() {
        byte[] first = new byte[32]; first[0] = 1;
        byte[] second = new byte[32]; second[0] = 2;
        AuthRequest request = AuthRequest.newBuilder().addScopeManifests(
                IntegrityScopeManifest.newBuilder().setScope("resourcepacks").setPresent(true)
                        .addEntries(file("pack/assets/a.txt", 1, first))
                        .addEntries(file("pack/pack.mcmeta", 2, second))).build();
        AuthenticatedManifest manifest = new AuthenticatedManifest(
                UUID.fromString("00000000-0000-0000-0000-000000000001"), "session-123456789012",
                SecurityPolicy.getDefaultInstance(), request, Instant.ofEpochMilli(NOW));
        return new AuthenticatedManifestObservationDeriver().derive(manifest).observations().stream()
                .filter(item -> "directory".equals(item.metadata().get("package_kind")))
                .findFirst().orElseThrow();
    }

    private static SharedProxyDispositionPolicyRuntime runtime(
            KeyPair keyPair, String root, com.ellan.mcace.protocol.generated.DispositionAction action)
            throws Exception {
        SignedDispositionPolicyDocument signed = signedCatalog(
                keyPair, DetectionMatchType.DETECTION_MATCH_CONTENT_ROOT, root, action);
        return new SharedProxyDispositionPolicyRuntime(
                ProxyFamily.VELOCITY, () -> signed, keyPair.getPublic(), CLOCK, Duration.ofSeconds(30));
    }

    private static SignedDispositionPolicyDocument signedCatalog(
            KeyPair keyPair, DetectionMatchType matchType, String hash,
            com.ellan.mcace.protocol.generated.DispositionAction action)
            throws Exception {
        DetectionSelector.Builder selector = DetectionSelector.newBuilder()
                .setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_RESOURCE_PACK)
                .setMatchType(matchType);
        DetectionCatalogEntry.Builder entryBuilder = DetectionCatalogEntry.newBuilder()
                .setEntryId("xray-directory")
                .setCategory(DetectionCatalogCategory.XRAY_RESOURCE_PACK)
                .setSelector(selector)
                .setConfidence(DetectionConfidence.DETECTION_CONFIDENCE_LOW)
                .setSuggestedAction(action)
                .setPlayerMessageKey("mcace.xray.directory")
                .setOperatorReason("controlled content-root test")
                .setFalsePositiveNotes("controlled test note")
                .setSourceId("test-source")
                .setSourceSummary("authenticated manifest test source");
        if (matchType == DetectionMatchType.DETECTION_MATCH_CONTENT_ROOT) {
            entryBuilder.setContentRootSha256Hex(hash);
        } else {
            entryBuilder.setSha256Hex(hash);
        }
        DetectionCatalogEntry entry = entryBuilder.build();
        DetectionCatalogSelection selection = DetectionCatalogSelection.newBuilder()
                .setEntryId("xray-directory").setEnabled(true).setFinalAction(action).build();
        var compiled = DispositionPolicyConfigurationCompiler.compile(
                DispositionPolicyConfiguration.newBuilder().addCatalogEntries(entry)
                        .addCatalogSelections(selection).build());
        DetectionRule rule = compiled.rules().getFirst().toBuilder()
                .setIntroducedAtEpochMs(NOW - 1_000)
                .setEffectiveFromEpochMs(NOW - 1_000)
                .setExpiresAtEpochMs(NOW + Duration.ofDays(1).toMillis()).build();
        DispositionPolicyDocument document = DispositionPolicyDocument.newBuilder()
                .setSchemaVersion(1).setPolicyId("content-root-test")
                .setVersion("content-root-1").setSequence(1)
                .setIssuedAtEpochMs(NOW - 1_000).setEffectiveFromEpochMs(NOW - 1_000)
                .setExpiresAtEpochMs(NOW + Duration.ofDays(1).toMillis())
                .setRolloutStage("OBSERVE")
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(keyPair.getPublic())))
                .addRules(rule).build();
        return DispositionPolicyDocuments.sign(document, keyPair.getPrivate(), keyPair.getPublic());
    }

    private static EvaluationContext context() {
        return new EvaluationContext(UUID.fromString("00000000-0000-0000-0000-000000000001"),
                "proxy-a", "survival", "world", "normal", Set.of("member"), Instant.ofEpochMilli(NOW));
    }

    private static FileEntry file(String path, long size, byte[] hash) {
        return FileEntry.newBuilder().setRelativePath(path).setFileSize(size)
                .setSha256(ByteString.copyFrom(hash)).build();
    }
}
