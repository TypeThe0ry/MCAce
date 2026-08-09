package com.ellan.mcace.core.disposition;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.generated.DetectionArtifactType;
import com.ellan.mcace.protocol.generated.DetectionCatalogCategory;
import com.ellan.mcace.protocol.generated.DetectionConfidence;
import com.ellan.mcace.protocol.generated.DetectionMatchType;
import com.ellan.mcace.protocol.generated.DetectionSelector;
import com.ellan.mcace.protocol.generated.DispositionAction;
import com.ellan.mcace.protocol.generated.DispositionPolicyConfiguration;
import com.ellan.mcace.protocol.generated.DispositionRuleConfiguration;
import com.ellan.mcace.protocol.generated.DetectionCatalogEntry;
import com.ellan.mcace.protocol.generated.DetectionCatalogSelection;
import com.google.protobuf.ByteString;
import java.util.List;
import org.junit.jupiter.api.Test;

final class DispositionPolicyConfigurationCompilerTest {
    private static final String HASH = "00".repeat(32);

    @Test
    void explicitlySelectedExactCatalogRulesCarryProvenanceAndPreviewCounts() {
        DispositionPolicyConfiguration configuration = config(
                entry("cheat", DetectionCatalogCategory.CHEAT_MOD,
                        DetectionMatchType.DETECTION_MATCH_EXACT_SHA256, HASH,
                        DispositionAction.DISPOSITION_DENY, false),
                entry("xray", DetectionCatalogCategory.XRAY_RESOURCE_PACK,
                        DetectionMatchType.DETECTION_MATCH_CONTENT_ROOT, HASH,
                        DispositionAction.DISPOSITION_QUARANTINE, true));

        DispositionPolicyConfigurationCompiler.CompiledDispositionConfiguration compiled =
                DispositionPolicyConfigurationCompiler.compile(configuration);

        assertEquals(2, compiled.rules().size());
        assertEquals("catalog.cheat", compiled.rules().get(0).getRuleId());
        assertEquals("cheat", compiled.rules().get(0).getCatalogEntryId());
        assertEquals(2, compiled.preview().selectedEntryCount());
        assertEquals(2, compiled.preview().compiledRuleCount());
        assertEquals(1, compiled.preview().actionCounts().get(
                com.ellan.mcace.core.disposition.DispositionAction.DENY));
        assertEquals(1, compiled.preview().actionCounts().get(
                com.ellan.mcace.core.disposition.DispositionAction.QUARANTINE));
        assertEquals(List.of("cheat", "xray"), compiled.preview().sourceSummaries().stream()
                .map(DispositionCatalogSourceSummary::entryId).toList());
        assertTrue(compiled.preview().sourceSummaries().stream()
                .allMatch(DispositionCatalogSourceSummary::legacy));
    }

    @Test
    void defaultEnabledIsDisplayOnlyAndPreviewWarningIsContentFree() {
        DetectionCatalogEntry entry = entry("unselected", DetectionCatalogCategory.AUTOMATION,
                DetectionMatchType.DETECTION_MATCH_ADMIN_CLASSIFICATION, "",
                DispositionAction.DISPOSITION_WARN, false).toBuilder().setDefaultEnabled(true).build();
        DispositionCatalogPreview preview = DispositionPolicyConfigurationCompiler.compile(
                DispositionPolicyConfiguration.newBuilder().addCatalogEntries(entry).build()).preview();

        assertEquals(0, preview.selectedEntryCount());
        assertTrue(preview.warnings().contains("UNSELECTED_CATALOG_ENTRY"));
        assertTrue(preview.warnings().stream().allMatch(warning -> warning.matches("[A-Z0-9_]+")));
    }

    @Test
    void nonExactCatalogCannotEscalateAndAccessibilityCannotBePunitive() {
        DetectionCatalogEntry metadata = entry("metadata", DetectionCatalogCategory.CHEAT_MOD,
                DetectionMatchType.DETECTION_MATCH_ADMIN_CLASSIFICATION, "",
                DispositionAction.DISPOSITION_WARN, true);
        for (DispositionAction action : List.of(
                DispositionAction.DISPOSITION_CHALLENGE,
                DispositionAction.DISPOSITION_LIMIT,
                DispositionAction.DISPOSITION_QUARANTINE,
                DispositionAction.DISPOSITION_DENY)) {
            assertThrows(IllegalArgumentException.class, () -> DispositionPolicyConfigurationCompiler.compile(
                    config(metadata.toBuilder().build(), selection("metadata", action, true))));
        }

        DetectionCatalogEntry accessibility = entry("assist", DetectionCatalogCategory.ACCESSIBILITY,
                DetectionMatchType.DETECTION_MATCH_ADMIN_CLASSIFICATION, "",
                DispositionAction.DISPOSITION_WARN, true);
        assertThrows(IllegalArgumentException.class, () -> DispositionPolicyConfigurationCompiler.compile(
                config(accessibility, selection("assist", DispositionAction.DISPOSITION_WARN, true))));
    }

    @Test
    void everyNonExactCatalogSelectionIsPreviewableAtWarnButCannotEscalate() {
        for (DetectionMatchType matchType : nonExactMatchTypes()) {
            String id = "catalog-" + matchType.getNumber();
            DetectionCatalogEntry entry = entry(id, DetectionCatalogCategory.CHEAT_MOD,
                    matchType, "", DispositionAction.DISPOSITION_WARN, false);
            var preview = DispositionPolicyConfigurationCompiler.compile(
                    config(entry, selection(id, DispositionAction.DISPOSITION_WARN, true))).preview();
            assertEquals(1, preview.selectedEntryCount(), () -> "WARN must remain available for " + matchType);
            assertEquals(1, preview.actionCounts().get(
                    com.ellan.mcace.core.disposition.DispositionAction.WARN));
            for (DispositionAction action : List.of(
                    DispositionAction.DISPOSITION_CHALLENGE,
                    DispositionAction.DISPOSITION_LIMIT,
                    DispositionAction.DISPOSITION_QUARANTINE,
                    DispositionAction.DISPOSITION_DENY)) {
                assertThrows(IllegalArgumentException.class, () -> DispositionPolicyConfigurationCompiler.compile(
                        config(entry, selection(id, action, true))),
                        () -> "catalog " + matchType + " must reject " + action);
            }
        }
    }

    @Test
    void manualSelectorsUseTheSameActionCeilingsAsCatalogSelectors() {
        for (DetectionMatchType matchType : nonExactMatchTypes()) {
            assertDoesNotThrow(() -> DispositionPolicyConfigurationCompiler.compile(
                    DispositionPolicyConfiguration.newBuilder().addRules(manual(
                            "warn-" + matchType.name(), matchType,
                            DispositionAction.DISPOSITION_WARN)).build()));
            for (DispositionAction action : List.of(
                    DispositionAction.DISPOSITION_CHALLENGE,
                    DispositionAction.DISPOSITION_LIMIT,
                    DispositionAction.DISPOSITION_QUARANTINE,
                    DispositionAction.DISPOSITION_DENY)) {
                assertThrows(IllegalArgumentException.class, () -> DispositionPolicyConfigurationCompiler.compile(
                        DispositionPolicyConfiguration.newBuilder().addRules(manual(
                                "unsafe-" + matchType.name() + "-" + action.name(), matchType, action)).build()),
                        () -> "manual " + matchType + " must reject " + action);
            }
        }

        assertDoesNotThrow(() -> DispositionPolicyConfigurationCompiler.compile(
                DispositionPolicyConfiguration.newBuilder().addRules(manual("exact-deny",
                        DetectionMatchType.DETECTION_MATCH_EXACT_SHA256,
                        DispositionAction.DISPOSITION_DENY)).build()));
        assertDoesNotThrow(() -> DispositionPolicyConfigurationCompiler.compile(
                DispositionPolicyConfiguration.newBuilder().addRules(manual("root-quarantine",
                        DetectionMatchType.DETECTION_MATCH_CONTENT_ROOT,
                        DispositionAction.DISPOSITION_QUARANTINE)).build()));
        assertThrows(IllegalArgumentException.class, () -> DispositionPolicyConfigurationCompiler.compile(
                DispositionPolicyConfiguration.newBuilder().addRules(manual("root-deny",
                        DetectionMatchType.DETECTION_MATCH_CONTENT_ROOT,
                        DispositionAction.DISPOSITION_DENY)).build()));
    }

    @Test
    void catalogSourceProvenanceIsAllOrNothingAndCopiedToTheSignedRuleInput() {
        DetectionCatalogEntry complete = entry("sourced", DetectionCatalogCategory.CHEAT_MOD,
                DetectionMatchType.DETECTION_MATCH_ADMIN_CLASSIFICATION, "",
                DispositionAction.DISPOSITION_OBSERVE, false).toBuilder()
                .setSourceUri("https://example.test/catalog")
                .setSourceRevision("8a4c9f1")
                .setSourceManifestPath("src/main/resources/fabric.mod.json")
                .setSourceRetrievedAtEpochMs(1L)
                .build();
        var compiled = DispositionPolicyConfigurationCompiler.compile(config(complete,
                selection("sourced", DispositionAction.DISPOSITION_OBSERVE, true)));
        var rule = compiled.rules().get(0);
        assertEquals("https://example.test/catalog", rule.getSourceUri());
        assertEquals("8a4c9f1", rule.getSourceRevision());
        assertEquals("src/main/resources/fabric.mod.json", rule.getSourceManifestPath());
        assertEquals(1L, rule.getSourceRetrievedAtEpochMs());
        var summary = compiled.preview().sourceSummaries().get(0);
        assertEquals("sourced", summary.entryId());
        assertEquals("https://example.test/catalog", summary.sourceUri());
        assertTrue(!summary.legacy());

        assertThrows(IllegalArgumentException.class, () -> DispositionPolicyConfigurationCompiler.compile(
                DispositionPolicyConfiguration.newBuilder().addCatalogEntries(
                        complete.toBuilder().clearSourceRevision().build()).build()));
        assertThrows(IllegalArgumentException.class, () -> DispositionPolicyConfigurationCompiler.compile(
                DispositionPolicyConfiguration.newBuilder().addCatalogEntries(
                        complete.toBuilder().setSourceUri("http://example.test/catalog").build()).build()));
        assertThrows(IllegalArgumentException.class, () -> DispositionPolicyConfigurationCompiler.compile(
                DispositionPolicyConfiguration.newBuilder().addCatalogEntries(
                        complete.toBuilder().setSourceManifestPath("../fabric.mod.json").build()).build()));

        DispositionRuleConfiguration manual = manual("manual-provenance",
                DetectionMatchType.DETECTION_MATCH_MOD_ID_VERSION, DispositionAction.DISPOSITION_WARN);
        assertThrows(IllegalArgumentException.class, () -> DispositionPolicyConfigurationCompiler.compile(
                DispositionPolicyConfiguration.newBuilder().addRules(manual.toBuilder()
                        .setRule(manual.getRule().toBuilder()
                                .setSourceUri("https://example.test/catalog")
                                .setSourceRevision("8a4c9f1")
                                .setSourceManifestPath("fabric.mod.json")
                                .setSourceRetrievedAtEpochMs(1L))
                        .build()).build()));
    }

    @Test
    void catalogContentRootDenyIsRejectedEarlyButOtherExactHighImpactActionsRemainAvailable() {
        DetectionCatalogEntry root = entry("pack-root", DetectionCatalogCategory.XRAY_RESOURCE_PACK,
                DetectionMatchType.DETECTION_MATCH_CONTENT_ROOT, HASH,
                DispositionAction.DISPOSITION_QUARANTINE, false);

        assertThrows(IllegalArgumentException.class, () -> DispositionPolicyConfigurationCompiler.compile(
                config(root, selection("pack-root", DispositionAction.DISPOSITION_DENY, true))));
        for (DispositionAction allowed : List.of(
                DispositionAction.DISPOSITION_WARN,
                DispositionAction.DISPOSITION_CHALLENGE,
                DispositionAction.DISPOSITION_LIMIT,
                DispositionAction.DISPOSITION_QUARANTINE)) {
            assertDoesNotThrow(() -> DispositionPolicyConfigurationCompiler.compile(
                    config(root, selection("pack-root", allowed, true))));
        }
    }

    @Test
    void rejectsMissingCatalogProvenanceRawHashesAndPlayerScope() {
        DetectionCatalogEntry missing = entry("missing", DetectionCatalogCategory.CHEAT_MOD,
                DetectionMatchType.DETECTION_MATCH_EXACT_SHA256, HASH,
                DispositionAction.DISPOSITION_DENY, true).toBuilder().clearSourceId().build();
        assertThrows(IllegalArgumentException.class, () -> DispositionPolicyConfigurationCompiler.compile(
                config(missing, selection("missing", DispositionAction.DISPOSITION_DENY, true))));

        DetectionSelector selector = DetectionSelector.newBuilder()
                .setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                .setMatchType(DetectionMatchType.DETECTION_MATCH_EXACT_SHA256)
                .setSha256(ByteString.copyFrom(new byte[32])).build();
        DetectionCatalogEntry raw = entry("raw", DetectionCatalogCategory.CHEAT_MOD,
                DetectionMatchType.DETECTION_MATCH_EXACT_SHA256, HASH,
                DispositionAction.DISPOSITION_WARN, false).toBuilder().setSelector(selector).build();
        assertThrows(IllegalArgumentException.class, () -> DispositionPolicyConfigurationCompiler.compile(
                config(raw, selection("raw", DispositionAction.DISPOSITION_WARN, true))));

        DetectionCatalogEntry player = entry("player", DetectionCatalogCategory.CHEAT_MOD,
                DetectionMatchType.DETECTION_MATCH_ADMIN_CLASSIFICATION, "",
                DispositionAction.DISPOSITION_WARN, false).toBuilder()
                .setScope(com.ellan.mcace.protocol.generated.DetectionRuleScope.newBuilder()
                        .addPlayerIds("00000000-0000-0000-0000-000000000001").build()).build();
        assertThrows(IllegalArgumentException.class, () -> DispositionPolicyConfigurationCompiler.compile(
                config(player, selection("player", DispositionAction.DISPOSITION_WARN, true))));
    }

    @Test
    void duplicateSelectionAndCatalogBudgetAreRejected() {
        DetectionCatalogEntry entry = entry("one", DetectionCatalogCategory.UTILITY,
                DetectionMatchType.DETECTION_MATCH_ADMIN_CLASSIFICATION, "",
                DispositionAction.DISPOSITION_OBSERVE, false);
        DispositionPolicyConfiguration duplicate = DispositionPolicyConfiguration.newBuilder()
                .addCatalogEntries(entry)
                .addCatalogSelections(selection("one", DispositionAction.DISPOSITION_OBSERVE, true))
                .addCatalogSelections(selection("one", DispositionAction.DISPOSITION_OBSERVE, true))
                .build();
        assertThrows(IllegalArgumentException.class,
                () -> DispositionPolicyConfigurationCompiler.compile(duplicate));

        DispositionPolicyConfiguration.Builder oversized = DispositionPolicyConfiguration.newBuilder();
        for (int index = 0; index <= DispositionPolicyConfigurationCompiler.MAX_CATALOG_ENTRIES; index++) {
            oversized.addCatalogEntries(entry("entry-" + index, DetectionCatalogCategory.UTILITY,
                    DetectionMatchType.DETECTION_MATCH_ADMIN_CLASSIFICATION, "",
                    DispositionAction.DISPOSITION_OBSERVE, false));
        }
        assertThrows(IllegalArgumentException.class,
                () -> DispositionPolicyConfigurationCompiler.compile(oversized.build()));
    }

    private static DispositionPolicyConfiguration config(DetectionCatalogEntry... entries) {
        DispositionPolicyConfiguration.Builder builder = DispositionPolicyConfiguration.newBuilder();
        for (DetectionCatalogEntry entry : entries) builder.addCatalogEntries(entry);
        for (DetectionCatalogEntry entry : entries) {
            if (entry.getEntryId().equals("cheat") || entry.getEntryId().equals("xray")) {
                builder.addCatalogSelections(selection(entry.getEntryId(),
                        entry.getEntryId().equals("cheat") ? DispositionAction.DISPOSITION_DENY
                                : DispositionAction.DISPOSITION_QUARANTINE, true));
            }
        }
        return builder.build();
    }

    private static DispositionPolicyConfiguration config(
            DetectionCatalogEntry entry, DetectionCatalogSelection selection) {
        return DispositionPolicyConfiguration.newBuilder()
                .addCatalogEntries(entry).addCatalogSelections(selection).build();
    }

    private static DetectionCatalogSelection selection(
            String id, DispositionAction action, boolean enabled) {
        return DetectionCatalogSelection.newBuilder().setEntryId(id).setEnabled(enabled)
                .setFinalAction(action).build();
    }

    private static DispositionRuleConfiguration manual(
            String id, DetectionMatchType matchType, DispositionAction action) {
        DetectionSelector.Builder selector = DetectionSelector.newBuilder()
                .setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                .setMatchType(matchType);
        DispositionRuleConfiguration.Builder configured = DispositionRuleConfiguration.newBuilder();
        if (matchType == DetectionMatchType.DETECTION_MATCH_EXACT_SHA256) {
            configured.setSha256Hex(HASH);
        } else if (matchType == DetectionMatchType.DETECTION_MATCH_CONTENT_ROOT) {
            configured.setContentRootSha256Hex(HASH);
        } else {
            switch (matchType) {
                case DETECTION_MATCH_MOD_ID_VERSION -> selector.setArtifactId("identity-" + id);
                case DETECTION_MATCH_SIGNER -> selector.setSigner("reviewed-signer");
                case DETECTION_MATCH_METADATA -> selector.putMetadata("classification", "automation");
                case DETECTION_MATCH_BEHAVIOR_CORRELATION -> selector.setBehaviorRuleId("reach-correlation");
                case DETECTION_MATCH_ADMIN_CLASSIFICATION -> selector.setArtifactId("reviewed-aid");
                default -> throw new IllegalArgumentException("unsupported manual selector: " + matchType);
            }
        }
        configured.setRule(com.ellan.mcace.protocol.generated.DetectionRule.newBuilder()
                .setRuleId(id).setConfidence(DetectionConfidence.DETECTION_CONFIDENCE_HIGH)
                .setDefaultAction(action).setSelector(selector));
        return configured.build();
    }

    private static List<DetectionMatchType> nonExactMatchTypes() {
        return List.of(
                DetectionMatchType.DETECTION_MATCH_MOD_ID_VERSION,
                DetectionMatchType.DETECTION_MATCH_SIGNER,
                DetectionMatchType.DETECTION_MATCH_METADATA,
                DetectionMatchType.DETECTION_MATCH_BEHAVIOR_CORRELATION,
                DetectionMatchType.DETECTION_MATCH_ADMIN_CLASSIFICATION);
    }

    private static DetectionCatalogEntry entry(
            String id, DetectionCatalogCategory category, DetectionMatchType matchType,
            String hash, DispositionAction suggested, boolean selected) {
        DetectionSelector.Builder selector = DetectionSelector.newBuilder()
                .setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_MOD)
                .setMatchType(matchType);
        switch (matchType) {
            case DETECTION_MATCH_MOD_ID_VERSION -> selector.setArtifactId("identity-" + id);
            case DETECTION_MATCH_SIGNER -> selector.setSigner("reviewed-signer");
            case DETECTION_MATCH_METADATA -> selector.putMetadata("classification", "automation");
            case DETECTION_MATCH_BEHAVIOR_CORRELATION -> selector.setBehaviorRuleId("reach-correlation");
            case DETECTION_MATCH_ADMIN_CLASSIFICATION -> selector.setArtifactId(id);
            case DETECTION_MATCH_EXACT_SHA256, DETECTION_MATCH_CONTENT_ROOT -> { }
            default -> throw new IllegalArgumentException("unsupported catalog selector: " + matchType);
        }
        DetectionCatalogEntry.Builder builder = DetectionCatalogEntry.newBuilder()
                .setEntryId(id).setCategory(category)
                .setSelector(selector.build())
                .setConfidence(DetectionConfidence.DETECTION_CONFIDENCE_HIGH)
                .setSuggestedAction(suggested)
                .setPlayerMessageKey("mcace.catalog." + id)
                .setOperatorReason("operator reason for " + id)
                .setFalsePositiveNotes("false-positive notes for " + id)
                .setSourceId("test-source")
                .setSourceSummary("test source summary")
                .setDefaultEnabled(selected);
        if (matchType == DetectionMatchType.DETECTION_MATCH_EXACT_SHA256) {
            builder.setSha256Hex(hash);
        } else if (matchType == DetectionMatchType.DETECTION_MATCH_CONTENT_ROOT) {
            builder.setContentRootSha256Hex(hash);
        }
        return builder.build();
    }
}
