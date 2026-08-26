package com.ellan.mcace.protocol.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.DetectionArtifactType;
import com.ellan.mcace.protocol.generated.DetectionCatalogCategory;
import com.ellan.mcace.protocol.generated.DetectionConfidence;
import com.ellan.mcace.protocol.generated.DetectionMatchType;
import com.ellan.mcace.protocol.generated.DetectionRule;
import com.ellan.mcace.protocol.generated.DetectionSelector;
import com.ellan.mcace.protocol.generated.DispositionAction;
import com.ellan.mcace.protocol.generated.DispositionPolicyDocument;
import com.ellan.mcace.protocol.generated.SignedDispositionPolicyDocument;
import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

final class DispositionPolicyDocumentsTest {
    private static final long NOW = 1_786_118_400_000L;
    private KeyPair identity;

    @BeforeEach
    void setUp() throws Exception {
        identity = Ed25519Keys.generate(new SecureRandom());
    }

    @Test
    void signsAndVerifiesBoundedPolicy() throws Exception {
        DispositionPolicyDocument policy = policy(rule(
                DetectionMatchType.DETECTION_MATCH_EXACT_SHA256,
                DispositionAction.DISPOSITION_WARN,
                false));
        SignedDispositionPolicyDocument signed = DispositionPolicyDocuments.sign(
                policy, identity.getPrivate(), identity.getPublic());

        DispositionPolicyDocument verified = DispositionPolicyDocuments.verify(
                signed, identity.getPublic(), fixedClock(), Duration.ofSeconds(30));

        assertEquals(policy, verified);
        assertEquals(32, DispositionPolicyDocuments.documentSha256(verified).length);
    }

    @Test
    void canonicalSelectorMetadataSurvivesTheSignedDocumentRoundTrip() throws Exception {
        DetectionRule canonical = rule(
                DetectionMatchType.DETECTION_MATCH_EXACT_SHA256,
                DispositionAction.DISPOSITION_WARN,
                false).toBuilder()
                .setSelector(DetectionSelector.newBuilder()
                        .setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_EXACT_SHA256)
                        .setSha256(ByteString.copyFrom(new byte[32]))
                        .putMetadata("loaded", "true")
                        .putMetadata("origin_manifest_matched", "true"))
                .build();

        SignedDispositionPolicyDocument signed = DispositionPolicyDocuments.sign(
                policy(canonical), identity.getPrivate(), identity.getPublic());
        DetectionSelector verified = DispositionPolicyDocuments.verify(
                signed, identity.getPublic(), fixedClock(), Duration.ZERO).getRules(0).getSelector();

        assertEquals(Map.of("loaded", "true", "origin_manifest_matched", "true"),
                verified.getMetadataMap());
    }

    @Test
    void rejectsNonCanonicalControlOrUnboundedSelectorMetadata() throws Exception {
        List<DetectionSelector> invalid = List.of(
                exactSelector().putMetadata(" loaded", "true").build(),
                exactSelector().putMetadata("loaded ", "true").build(),
                exactSelector().putMetadata("\u2003loaded", "true").build(),
                exactSelector().putMetadata("lo\naded", "true").build(),
                exactSelector().putMetadata("k".repeat(129), "true").build(),
                exactSelector().putMetadata("loaded", " true").build(),
                exactSelector().putMetadata("loaded", "true ").build(),
                exactSelector().putMetadata("loaded", "tr\nue").build(),
                exactSelector().putMetadata("loaded", "v".repeat(257)).build());

        for (DetectionSelector selector : invalid) {
            DetectionRule candidate = rule(DetectionMatchType.DETECTION_MATCH_EXACT_SHA256,
                    DispositionAction.DISPOSITION_WARN, false).toBuilder().setSelector(selector).build();
            assertThrows(PolicyException.class, () -> DispositionPolicyDocuments.sign(
                    policy(candidate), identity.getPrivate(), identity.getPublic()));
        }

        DetectionSelector.Builder oversized = exactSelector();
        for (int index = 0; index < 65; index++) {
            oversized.putMetadata("key-" + index, "value-" + index);
        }
        DetectionRule tooMany = rule(DetectionMatchType.DETECTION_MATCH_EXACT_SHA256,
                DispositionAction.DISPOSITION_WARN, false).toBuilder().setSelector(oversized).build();
        assertThrows(PolicyException.class, () -> DispositionPolicyDocuments.sign(
                policy(tooMany), identity.getPrivate(), identity.getPublic()));
    }

    @Test
    void rejectsMetadataThatDuplicatesDerivedSelectorFields() throws Exception {
        List<DetectionSelector> invalid = List.of(
                DetectionSelector.newBuilder()
                        .setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_SIGNER)
                        .setSigner("trusted-signer")
                        .putMetadata("signer", "different-signer")
                        .build(),
                DetectionSelector.newBuilder()
                        .setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_RESOURCE_PACK)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_CONTENT_ROOT)
                        .setContentRootSha256(ByteString.copyFrom(new byte[32]))
                        .putMetadata("content_root_sha256", "11".repeat(32))
                        .build(),
                DetectionSelector.newBuilder()
                        .setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_ADMIN_CLASSIFICATION)
                        .setArtifactId("reviewed-aid")
                        .putMetadata("admin_classification", "different-aid")
                        .build());

        for (DetectionSelector selector : invalid) {
            DetectionRule candidate = rule(selector.getMatchType(), DispositionAction.DISPOSITION_WARN, false)
                    .toBuilder().setSelector(selector).build();
            assertThrows(PolicyException.class,
                    () -> DispositionPolicyDocuments.validateStructure(policy(candidate)));
        }
    }

    @Test
    void rejectsTamperingAndExpiredPolicy() throws Exception {
        SignedDispositionPolicyDocument signed = DispositionPolicyDocuments.sign(
                policy(rule(DetectionMatchType.DETECTION_MATCH_EXACT_SHA256,
                        DispositionAction.DISPOSITION_WARN, false)),
                identity.getPrivate(), identity.getPublic());
        SignedDispositionPolicyDocument tampered = signed.toBuilder()
                .setDocument(signed.getDocument().concat(ByteString.copyFromUtf8("x")))
                .build();

        assertThrows(PolicyException.class, () -> DispositionPolicyDocuments.verifySignatureAndStructure(
                tampered, identity.getPublic()));
        Clock expired = Clock.fixed(Instant.ofEpochMilli(NOW + Duration.ofDays(2).toMillis()), ZoneOffset.UTC);
        assertThrows(PolicyException.class, () -> DispositionPolicyDocuments.verify(
                signed, identity.getPublic(), expired, Duration.ZERO));
    }

    @Test
    void rejectsNameOnlyDenyAndFoundationAllow() throws Exception {
        assertThrows(PolicyException.class, () -> DispositionPolicyDocuments.validateStructure(policy(rule(
                DetectionMatchType.DETECTION_MATCH_MOD_ID_VERSION,
                DispositionAction.DISPOSITION_DENY,
                false))));
        assertThrows(PolicyException.class, () -> DispositionPolicyDocuments.validateStructure(policy(rule(
                DetectionMatchType.DETECTION_MATCH_EXACT_SHA256,
                DispositionAction.DISPOSITION_ALLOW,
                true))));
        assertThrows(PolicyException.class, () -> DispositionPolicyDocuments.validateStructure(policy(rule(
                DetectionMatchType.DETECTION_MATCH_ADMIN_CLASSIFICATION,
                DispositionAction.DISPOSITION_QUARANTINE,
                false))));
    }

    @Test
    void selectorActionGuardCoversEveryConcreteCombination() throws Exception {
        for (DetectionMatchType matchType : DetectionMatchType.values()) {
            if (matchType == DetectionMatchType.DETECTION_MATCH_TYPE_UNSPECIFIED
                    || matchType == DetectionMatchType.UNRECOGNIZED) {
                continue;
            }
            for (DispositionAction action : DispositionAction.values()) {
                if (action == DispositionAction.DISPOSITION_ACTION_UNSPECIFIED
                        || action == DispositionAction.UNRECOGNIZED) {
                    continue;
                }
                boolean accepted = switch (matchType) {
                    case DETECTION_MATCH_EXACT_SHA256 -> true;
                    case DETECTION_MATCH_CONTENT_ROOT ->
                            action.getNumber() <= DispositionAction.DISPOSITION_QUARANTINE.getNumber();
                    default -> action.getNumber() <= DispositionAction.DISPOSITION_WARN.getNumber();
                };
                DetectionRule candidate = rule(matchType, action, false);
                if (accepted) {
                    DispositionPolicyDocuments.validateStructure(policy(candidate));
                } else {
                    assertThrows(PolicyException.class,
                            () -> DispositionPolicyDocuments.validateStructure(policy(candidate)),
                            () -> matchType + " must reject " + action);
                }
            }
        }
    }

    @Test
    void signedDocumentPathCannotElevateWeakSelectors() throws Exception {
        for (DetectionMatchType matchType : java.util.List.of(
                DetectionMatchType.DETECTION_MATCH_MOD_ID_VERSION,
                DetectionMatchType.DETECTION_MATCH_SIGNER,
                DetectionMatchType.DETECTION_MATCH_METADATA,
                DetectionMatchType.DETECTION_MATCH_BEHAVIOR_CORRELATION,
                DetectionMatchType.DETECTION_MATCH_ADMIN_CLASSIFICATION)) {
            DetectionRule candidate = rule(matchType, DispositionAction.DISPOSITION_CHALLENGE, false);
            assertThrows(PolicyException.class, () -> DispositionPolicyDocuments.sign(
                    policy(candidate), identity.getPrivate(), identity.getPublic()),
                    () -> "signed policy must reject non-exact " + matchType + " above WARN");
        }

        assertThrows(PolicyException.class, () -> DispositionPolicyDocuments.sign(policy(rule(
                DetectionMatchType.DETECTION_MATCH_CONTENT_ROOT,
                DispositionAction.DISPOSITION_DENY,
                false)), identity.getPrivate(), identity.getPublic()));

        SignedDispositionPolicyDocument signed = DispositionPolicyDocuments.sign(policy(rule(
                DetectionMatchType.DETECTION_MATCH_EXACT_SHA256,
                DispositionAction.DISPOSITION_DENY,
                false)), identity.getPrivate(), identity.getPublic());
        assertEquals(DispositionAction.DISPOSITION_DENY,
                DispositionPolicyDocuments.verify(signed, identity.getPublic(), fixedClock(), Duration.ZERO)
                        .getRules(0).getDefaultAction());
    }

    @Test
    void rejectsContentRootDeny() throws Exception {
        assertThrows(PolicyException.class, () -> DispositionPolicyDocuments.validateStructure(policy(rule(
                DetectionMatchType.DETECTION_MATCH_CONTENT_ROOT,
                DispositionAction.DISPOSITION_DENY,
                false))));
    }

    @Test
    void foundationProtocolIntegrityRulesRetainTheirExistingHighImpactContract() throws Exception {
        DispositionPolicyDocuments.validateStructure(policy(rule(
                DetectionMatchType.DETECTION_MATCH_MOD_ID_VERSION,
                DispositionAction.DISPOSITION_DENY,
                true)));
    }

    @Test
    void validatesCatalogProvenanceAndRejectsForgedPartialProvenance() throws Exception {
        DetectionRule catalogRule = catalogRule();
        DispositionPolicyDocuments.validateStructure(policy(catalogRule));

        DetectionRule forged = catalogRule.toBuilder().clearSourceSummary().build();
        assertThrows(PolicyException.class, () -> DispositionPolicyDocuments.validateStructure(policy(forged)));
    }

    @Test
    void legacyCatalogProvenanceRemainsCompatibleWhenAllStructuredFieldsAreAbsent() throws Exception {
        SignedDispositionPolicyDocument signed = DispositionPolicyDocuments.sign(
                policy(catalogRule()), identity.getPrivate(), identity.getPublic());
        DetectionRule verified = DispositionPolicyDocuments.verify(
                signed, identity.getPublic(), fixedClock(), Duration.ZERO).getRules(0);
        assertEquals("", verified.getSourceUri());
        assertEquals("", verified.getSourceRevision());
        assertEquals("", verified.getSourceManifestPath());
        assertEquals(0L, verified.getSourceRetrievedAtEpochMs());
    }

    @Test
    void completeStructuredCatalogProvenanceSurvivesSignedRoundTrip() throws Exception {
        DetectionRule structured = structuredCatalogRule();
        SignedDispositionPolicyDocument signed = DispositionPolicyDocuments.sign(
                policy(structured), identity.getPrivate(), identity.getPublic());
        DetectionRule verified = DispositionPolicyDocuments.verify(
                signed, identity.getPublic(), fixedClock(), Duration.ZERO).getRules(0);
        assertEquals(structured.getSourceUri(), verified.getSourceUri());
        assertEquals(structured.getSourceRevision(), verified.getSourceRevision());
        assertEquals(structured.getSourceManifestPath(), verified.getSourceManifestPath());
        assertEquals(structured.getSourceRetrievedAtEpochMs(), verified.getSourceRetrievedAtEpochMs());
    }

    @Test
    void rejectsPartialOrUnsafeStructuredCatalogProvenance() throws Exception {
        DetectionRule partial = catalogRule().toBuilder()
                .setSourceUri("https://github.com/example/repository")
                .build();
        assertThrows(PolicyException.class, () -> DispositionPolicyDocuments.validateStructure(policy(partial)));

        for (String sourceUri : java.util.List.of(
                "http://github.com/example/repository",
                "https://operator@github.com/example/repository",
                "https://github.com/example/repository#fragment",
                "https:/missing-host")) {
            DetectionRule invalid = structuredCatalogRule().toBuilder().setSourceUri(sourceUri).build();
            assertThrows(PolicyException.class, () -> DispositionPolicyDocuments.validateStructure(policy(invalid)));
        }
        for (String path : java.util.List.of("/absolute/manifest.json", "src/../manifest.json", "src\\manifest.json")) {
            DetectionRule invalid = structuredCatalogRule().toBuilder().setSourceManifestPath(path).build();
            assertThrows(PolicyException.class, () -> DispositionPolicyDocuments.validateStructure(policy(invalid)));
        }
        DetectionRule lateRetrieval = structuredCatalogRule().toBuilder()
                .setSourceRetrievedAtEpochMs(NOW)
                .build();
        assertThrows(PolicyException.class, () -> DispositionPolicyDocuments.validateStructure(policy(lateRetrieval)));
    }

    private DispositionPolicyDocument policy(DetectionRule rule) throws PolicyException {
        return DispositionPolicyDocument.newBuilder()
                .setSchemaVersion(1)
                .setPolicyId("network-default")
                .setVersion("2026.08.08-1")
                .setSequence(1)
                .setIssuedAtEpochMs(NOW - 1_000)
                .setEffectiveFromEpochMs(NOW - 500)
                .setExpiresAtEpochMs(NOW + Duration.ofDays(1).toMillis())
                .setRolloutStage("OBSERVE")
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(identity.getPublic())))
                .addRules(rule)
                .build();
    }

    private static DetectionRule catalogRule() {
        return rule(DetectionMatchType.DETECTION_MATCH_EXACT_SHA256,
                DispositionAction.DISPOSITION_DENY,
                false).toBuilder()
                .setCatalogEntryId("catalog-cheat")
                .setCatalogCategory(DetectionCatalogCategory.CHEAT_MOD)
                .setSourceId("test-source")
                .setSourceSummary("controlled test source")
                .setOperatorReason("confirmed test artifact")
                .setFalsePositiveNotes("test note")
                .build();
    }

    private static DetectionRule structuredCatalogRule() {
        return catalogRule().toBuilder()
                .setSourceUri("https://github.com/example/repository/blob/0123456789abcdef/fabric.mod.json")
                .setSourceRevision("0123456789abcdef")
                .setSourceManifestPath("src/main/resources/fabric.mod.json")
                .setSourceRetrievedAtEpochMs(NOW - 2_000L)
                .build();
    }

    private static DetectionRule rule(
            DetectionMatchType matchType, DispositionAction action, boolean foundation) {
        DetectionSelector.Builder selector = DetectionSelector.newBuilder()
                .setArtifactType(foundation
                        ? DetectionArtifactType.DETECTION_ARTIFACT_PROTOCOL
                        : DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                .setMatchType(matchType);
        switch (matchType) {
            case DETECTION_MATCH_EXACT_SHA256 -> selector.setSha256(ByteString.copyFrom(new byte[32]));
            case DETECTION_MATCH_MOD_ID_VERSION, DETECTION_MATCH_ADMIN_CLASSIFICATION ->
                    selector.setArtifactId("example.mod");
            case DETECTION_MATCH_SIGNER -> selector.setSigner("example-signer");
            case DETECTION_MATCH_CONTENT_ROOT -> selector.setContentRootSha256(ByteString.copyFrom(new byte[32]));
            case DETECTION_MATCH_METADATA -> selector.putMetadata("classification", "example");
            case DETECTION_MATCH_BEHAVIOR_CORRELATION -> selector.setBehaviorRuleId("example-behavior");
            case DETECTION_MATCH_TYPE_UNSPECIFIED, UNRECOGNIZED -> throw new IllegalArgumentException("unsupported test selector");
        }
        return DetectionRule.newBuilder()
                .setRuleId("rule-1")
                .setRevision(1)
                .setPriority(100)
                .setSelector(selector)
                .setConfidence(DetectionConfidence.DETECTION_CONFIDENCE_HIGH)
                .setDefaultAction(action)
                .setFoundationSecurity(foundation)
                .setIntroducedAtEpochMs(NOW - 1_000)
                .setEffectiveFromEpochMs(NOW - 500)
                .setExpiresAtEpochMs(NOW + Duration.ofHours(1).toMillis())
                .build();
    }

    private static DetectionSelector.Builder exactSelector() {
        return DetectionSelector.newBuilder()
                .setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                .setMatchType(DetectionMatchType.DETECTION_MATCH_EXACT_SHA256)
                .setSha256(ByteString.copyFrom(new byte[32]));
    }

    private static Clock fixedClock() {
        return Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC);
    }
}
