package com.ellan.mcace.core.disposition;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.protocol.generated.DetectionArtifactType;
import com.ellan.mcace.protocol.generated.DetectionConfidence;
import com.ellan.mcace.protocol.generated.DetectionMatchType;
import com.ellan.mcace.protocol.generated.DetectionRule;
import com.ellan.mcace.protocol.generated.DetectionSelector;
import com.ellan.mcace.protocol.generated.DispositionPolicyDocument;
import com.google.protobuf.ByteString;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class DispositionPolicyCompilerTest {
    private static final ByteString HASH = ByteString.copyFrom(new byte[32]);
    private static final long ISSUED = 1_700_000_000_000L;
    private static final long EFFECTIVE = ISSUED + 1_000L;
    private static final long EXPIRES = EFFECTIVE + 60_000L;

    @Test
    void mapsEverySupportedEnumExactly() {
        assertEquals(List.of(ArtifactType.MOD, ArtifactType.RESOURCE_PACK, ArtifactType.SHADER_PACK,
                        ArtifactType.CONFIG, ArtifactType.BEHAVIOR, ArtifactType.PROTOCOL),
                List.of(DetectionArtifactType.DETECTION_ARTIFACT_MOD, DetectionArtifactType.DETECTION_ARTIFACT_RESOURCE_PACK,
                                DetectionArtifactType.DETECTION_ARTIFACT_SHADER_PACK, DetectionArtifactType.DETECTION_ARTIFACT_CONFIG,
                                DetectionArtifactType.DETECTION_ARTIFACT_BEHAVIOR, DetectionArtifactType.DETECTION_ARTIFACT_PROTOCOL)
                        .stream().map(DispositionPolicyCompiler::artifactType).toList());
        assertEquals(List.of(Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH, Confidence.CONFIRMED),
                List.of(DetectionConfidence.DETECTION_CONFIDENCE_LOW, DetectionConfidence.DETECTION_CONFIDENCE_MEDIUM,
                                DetectionConfidence.DETECTION_CONFIDENCE_HIGH, DetectionConfidence.DETECTION_CONFIDENCE_CONFIRMED)
                        .stream().map(DispositionPolicyCompiler::confidence).toList());
        assertEquals(List.of(DispositionAction.ALLOW, DispositionAction.OBSERVE, DispositionAction.NOTICE,
                        DispositionAction.WARN, DispositionAction.CHALLENGE, DispositionAction.LIMIT,
                        DispositionAction.QUARANTINE, DispositionAction.DENY),
                List.of(com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_ALLOW,
                                com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_OBSERVE,
                                com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_NOTICE,
                                com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_WARN,
                                com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_CHALLENGE,
                                com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_LIMIT,
                                com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_QUARANTINE,
                                com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_DENY)
                        .stream().map(DispositionPolicyCompiler::action).toList());
        assertEquals(List.of(ObservationOrigin.SERVER_CONFIRMED, ObservationOrigin.CLIENT_REPORTED,
                        ObservationOrigin.INFERRED, ObservationOrigin.ADMIN_REVIEWED, ObservationOrigin.UNAVAILABLE),
                List.of(com.ellan.mcace.protocol.generated.ObservationOrigin.OBSERVATION_ORIGIN_SERVER_CONFIRMED,
                                com.ellan.mcace.protocol.generated.ObservationOrigin.OBSERVATION_ORIGIN_CLIENT_REPORTED,
                                com.ellan.mcace.protocol.generated.ObservationOrigin.OBSERVATION_ORIGIN_INFERRED,
                                com.ellan.mcace.protocol.generated.ObservationOrigin.OBSERVATION_ORIGIN_ADMIN_REVIEWED,
                                com.ellan.mcace.protocol.generated.ObservationOrigin.OBSERVATION_ORIGIN_UNAVAILABLE)
                        .stream().map(DispositionPolicyCompiler::observationOrigin).toList());
    }

    @Test
    void compilesSelectorFamiliesScopesAndReviewFieldsWithoutLoss() {
        DetectionRule rule = baseRule("rule").setSelector(DetectionSelector.newBuilder()
                        .setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_METADATA).putMetadata("class", "xray"))
                .setDefaultAction(com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_ALLOW)
                .setPlayerMessageKey("mcace.xray").setFalsePositiveNotes("review resource pack")
                .setOperatorReason("known ore visibility aid").setRevision(7).setException(true)
                .build();
        DispositionPolicy policy = DispositionPolicyCompiler.compileVerified(document(rule.toBuilder()
                .setScope(com.ellan.mcace.protocol.generated.DetectionRuleScope.newBuilder()
                        .addProxyIds("proxy-b").addProxyIds("proxy-a").addBackendIds("rpg")
                        .addGameModes("survival").addPermissionGroups("vip").addWorldIds("overworld")
                        .addPlayerIds("00000000-0000-0000-0000-000000000001"))
                .build()));
        DispositionRule compiled = policy.rules().getFirst();
        assertEquals("proxy-a", compiled.scope().proxy());
        assertEquals("rpg", compiled.scope().backend());
        assertEquals("survival", compiled.scope().gameMode());
        assertEquals("vip", compiled.scope().permissionGroup());
        assertEquals("overworld", compiled.scope().world());
        assertEquals(UUID.fromString("00000000-0000-0000-0000-000000000001"), compiled.scope().playerId());
        assertEquals(Map.of("class", "xray"), compiled.selector().requiredMetadata());
        assertEquals("rule", compiled.explanation().sourceRuleId());
        assertEquals("mcace.xray", compiled.explanation().playerMessageKey());
        assertEquals("review resource pack", compiled.explanation().falsePositiveNotes());
        assertEquals("known ore visibility aid", compiled.explanation().operatorReason());
        assertEquals(7L, compiled.explanation().revision());
        assertFalse(compiled.disabled());
        assertEquals("policy", policy.metadata().policyId());
        assertEquals(1L, policy.metadata().sequence());
    }

    @Test
    void expandsScopesInStableOrderAndRetainsDisabledRulesForAudit() {
        DetectionRule rule = baseRule("rule").setDisabled(true).setScope(com.ellan.mcace.protocol.generated.DetectionRuleScope.newBuilder()
                .addProxyIds("z").addProxyIds("a").addBackendIds("two").addBackendIds("one")).build();
        List<DispositionRule> first = DispositionPolicyCompiler.compileVerified(document(rule)).rules();
        List<DispositionRule> second = DispositionPolicyCompiler.compileVerified(document(rule)).rules();
        assertEquals(first, second);
        assertEquals(List.of("rule~scope~0", "rule~scope~1", "rule~scope~2", "rule~scope~3"),
                first.stream().map(DispositionRule::ruleId).toList());
        assertEquals("a", first.getFirst().scope().proxy());
        assertEquals("one", first.getFirst().scope().backend());
        assertEquals("rule", first.getFirst().explanation().sourceRuleId());
        assertFalse(first.getFirst().activeAt(java.time.Instant.ofEpochMilli(EFFECTIVE)));
    }

    @Test
    void mapsEverySelectorFamilyWithoutChangingItsMeaning() {
        List<DetectionRule> rules = List.of(
                baseRule("hash").build(),
                baseRule("id").setSelector(DetectionSelector.newBuilder().setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_MOD_ID_VERSION).setArtifactId("aid").setVersionConstraint("1.2.3")).build(),
                baseRule("signer").setSelector(DetectionSelector.newBuilder().setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_SIGNER).setSigner("trusted-signer")).build(),
                baseRule("root").setSelector(DetectionSelector.newBuilder().setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_RESOURCE_PACK)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_CONTENT_ROOT).setContentRootSha256(HASH)).build(),
                baseRule("metadata").setSelector(DetectionSelector.newBuilder().setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_CONFIG)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_METADATA).putMetadata("kind", "automation")).build(),
                baseRule("behavior").setSelector(DetectionSelector.newBuilder().setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_BEHAVIOR)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_BEHAVIOR_CORRELATION).setBehaviorRuleId("reach-correlation")).build(),
                baseRule("classification").setSelector(DetectionSelector.newBuilder().setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_ADMIN_CLASSIFICATION).setArtifactId("reviewed-aid")).build());
        List<ArtifactSelector> selectors = DispositionPolicyCompiler.compileVerified(document(rules)).rules().stream()
                .map(DispositionRule::selector).toList();
        assertEquals(List.of(MatchType.EXACT_HASH, MatchType.EXACT_ID, MatchType.METADATA, MatchType.METADATA,
                        MatchType.METADATA, MatchType.EXACT_ID, MatchType.METADATA),
                selectors.stream().map(ArtifactSelector::matchType).toList());
        assertEquals("aid", selectors.get(1).value());
        assertEquals("1.2.3", selectors.get(1).minimumVersion());
        assertEquals(Map.of("signer", "trusted-signer"), selectors.get(2).requiredMetadata());
        assertEquals(Map.of("content_root_sha256", "0000000000000000000000000000000000000000000000000000000000000000"), selectors.get(3).requiredMetadata());
        assertEquals(ArtifactType.CONFIG, selectors.get(4).type());
        assertEquals("reach-correlation", selectors.get(5).value());
        assertEquals(Map.of("admin_classification", "reviewed-aid"), selectors.get(6).requiredMetadata());
    }

    @Test
    void rejectsUnknownAndUnsafeValues() {
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.artifactType(DetectionArtifactType.DETECTION_ARTIFACT_TYPE_UNSPECIFIED));
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.artifactType(DetectionArtifactType.UNRECOGNIZED));
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.confidence(DetectionConfidence.DETECTION_CONFIDENCE_UNSPECIFIED));
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.confidence(DetectionConfidence.UNRECOGNIZED));
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.action(com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_ACTION_UNSPECIFIED));
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.action(com.ellan.mcace.protocol.generated.DispositionAction.UNRECOGNIZED));
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.observationOrigin(com.ellan.mcace.protocol.generated.ObservationOrigin.OBSERVATION_ORIGIN_UNSPECIFIED));
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.observationOrigin(com.ellan.mcace.protocol.generated.ObservationOrigin.UNRECOGNIZED));
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.compileVerified(document(baseRule("priority").setPriority(-1).build())));
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.compileVerified(document(baseRule("versions")
                .setSelector(DetectionSelector.newBuilder().setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_MOD_ID_VERSION).setArtifactId("aid").setVersionConstraint(">1.2"))
                .build())));
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.compileVerified(document(baseRule("dupe-scope")
                .setScope(com.ellan.mcace.protocol.generated.DetectionRuleScope.newBuilder().addProxyIds("p").addProxyIds("p")).build())));
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.compileVerified(document(baseRule("wide-scope")
                .setScope(oversizedScope()).build())));
    }

    @Test
    void neverLetsNameOnlyDenyReachTheCore() {
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.compileVerified(document(baseRule("name-only")
                .setDefaultAction(com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_DENY)
                .setSelector(DetectionSelector.newBuilder().setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_MOD_ID_VERSION).setArtifactId("suspicious-name"))
                .build())));
    }

    @Test
    void validatesAndDeterministicallyExpandsExactPlayerScopes() {
        String firstPlayer = "00000000-0000-0000-0000-000000000001";
        String secondPlayer = "00000000-0000-0000-0000-000000000002";
        DetectionRule rule = baseRule("player-scope").setScope(com.ellan.mcace.protocol.generated.DetectionRuleScope.newBuilder()
                .addProxyIds("proxy-b").addProxyIds("proxy-a").addPlayerIds(secondPlayer).addPlayerIds(firstPlayer)).build();
        List<DispositionRule> compiled = DispositionPolicyCompiler.compileVerified(document(rule)).rules();
        assertEquals(4, compiled.size());
        assertEquals("proxy-a", compiled.get(0).scope().proxy());
        assertEquals(UUID.fromString(firstPlayer), compiled.get(0).scope().playerId());
        assertEquals(UUID.fromString(secondPlayer), compiled.get(1).scope().playerId());
        assertEquals("proxy-b", compiled.get(2).scope().proxy());
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.compileVerified(document(
                baseRule("bad-player").setScope(com.ellan.mcace.protocol.generated.DetectionRuleScope.newBuilder()
                        .addPlayerIds("not-a-uuid")).build())));
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.compileVerified(document(
                baseRule("duplicate-player").setScope(com.ellan.mcace.protocol.generated.DetectionRuleScope.newBuilder()
                        .addPlayerIds(firstPlayer).addPlayerIds(firstPlayer)).build())));
        assertThrows(DispositionPolicyCompileException.class, () -> DispositionPolicyCompiler.compileVerified(document(
                baseRule("bad-exception").setDefaultAction(com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_ALLOW)
                        .setException(true).build())));
    }

    private static DispositionPolicyDocument document(DetectionRule rule) {
        return document(List.of(rule));
    }

    private static DispositionPolicyDocument document(List<DetectionRule> rules) {
        return DispositionPolicyDocument.newBuilder().setSchemaVersion(1).setPolicyId("policy").setVersion("v1")
                .setSequence(1).setIssuedAtEpochMs(ISSUED).setEffectiveFromEpochMs(EFFECTIVE).setExpiresAtEpochMs(EXPIRES)
                .setRolloutStage("OBSERVE").setSignerKeyIdSha256(HASH).addAllRules(rules).build();
    }

    private static DetectionRule.Builder baseRule(String id) {
        return DetectionRule.newBuilder().setRuleId(id).setPriority(1).setConfidence(DetectionConfidence.DETECTION_CONFIDENCE_HIGH)
                .setDefaultAction(com.ellan.mcace.protocol.generated.DispositionAction.DISPOSITION_WARN)
                .setIntroducedAtEpochMs(ISSUED).setEffectiveFromEpochMs(EFFECTIVE).setExpiresAtEpochMs(EXPIRES).setRevision(1)
                .setSelector(DetectionSelector.newBuilder().setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_EXACT_SHA256).setSha256(HASH));
    }

    private static com.ellan.mcace.protocol.generated.DetectionRuleScope oversizedScope() {
        com.ellan.mcace.protocol.generated.DetectionRuleScope.Builder scope = com.ellan.mcace.protocol.generated.DetectionRuleScope.newBuilder();
        for (int index = 0; index < 6; index++) {
            scope.addProxyIds("p" + index).addBackendIds("b" + index).addGameModes("g" + index)
                    .addPermissionGroups("group" + index).addWorldIds("w" + index);
        }
        return scope.build();
    }
}
