package com.ellan.mcace.core.disposition;

import com.ellan.mcace.protocol.generated.DetectionArtifactType;
import com.ellan.mcace.protocol.generated.DetectionCatalogCategory;
import com.ellan.mcace.protocol.generated.DetectionConfidence;
import com.ellan.mcace.protocol.generated.DetectionMatchType;
import com.ellan.mcace.protocol.generated.DetectionRule;
import com.ellan.mcace.protocol.generated.DetectionRuleScope;
import com.ellan.mcace.protocol.generated.DetectionSelector;
import com.ellan.mcace.protocol.generated.DispositionAction;
import com.ellan.mcace.protocol.generated.DispositionPolicyConfiguration;
import com.ellan.mcace.protocol.generated.DispositionRuleConfiguration;
import com.ellan.mcace.protocol.generated.DetectionCatalogEntry;
import com.ellan.mcace.protocol.generated.DetectionCatalogSelection;
import com.ellan.mcace.protocol.policy.PolicyException;
import com.google.protobuf.ByteString;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Validates and deterministically merges unsigned catalog selections with hand-written rules.
 * This class never signs, writes, publishes, or selects a catalog entry from its default flag.
 */
public final class DispositionPolicyConfigurationCompiler {
    public static final int MAX_CATALOG_ENTRIES = 4_096;
    public static final int MAX_CATALOG_SELECTIONS = 4_096;
    public static final int MAX_COMPILED_RULES = 4_096;
    private static final int MAX_TEXT_CHARS = 2_048;
    private static final int MAX_IDENTIFIER_CHARS = 128;

    private DispositionPolicyConfigurationCompiler() { }

    public static CompiledDispositionConfiguration compile(
            DispositionPolicyConfiguration configuration) {
        if (configuration == null) throw failure("catalog configuration is null");
        if (configuration.getCatalogEntriesCount() > MAX_CATALOG_ENTRIES) {
            throw failure("catalog entry budget exceeded");
        }
        if (configuration.getCatalogSelectionsCount() > MAX_CATALOG_SELECTIONS) {
            throw failure("catalog selection budget exceeded");
        }

        Map<String, DetectionCatalogEntry> entries = new HashMap<>();
        for (DetectionCatalogEntry entry : configuration.getCatalogEntriesList()) {
            validateEntry(entry);
            if (entries.put(entry.getEntryId(), entry) != null) {
                throw failure("duplicate catalog entry id: " + entry.getEntryId());
            }
        }

        Map<String, DetectionCatalogSelection> selections = new HashMap<>();
        for (DetectionCatalogSelection selection : configuration.getCatalogSelectionsList()) {
            validateSelection(selection);
            if (selections.put(selection.getEntryId(), selection) != null) {
                throw failure("duplicate catalog selection id: " + selection.getEntryId());
            }
            if (!entries.containsKey(selection.getEntryId())) {
                throw failure("catalog selection references an unknown entry: " + selection.getEntryId());
            }
        }

        List<DetectionRule> rules = new ArrayList<>();
        EnumMap<DetectionCatalogCategory, Integer> categoryCounts =
                new EnumMap<>(DetectionCatalogCategory.class);
        EnumMap<com.ellan.mcace.core.disposition.DispositionAction, Integer> actionCounts =
                new EnumMap<>(com.ellan.mcace.core.disposition.DispositionAction.class);
        List<DispositionCatalogSourceSummary> sourceSummaries = new ArrayList<>();
        int selectedEntries = 0;
        for (DetectionCatalogEntry entry : entries.values().stream()
                .sorted(Comparator.comparing(DetectionCatalogEntry::getEntryId)).toList()) {
            CatalogSourceProvenance source = CatalogSourceProvenance.from(entry);
            sourceSummaries.add(new DispositionCatalogSourceSummary(entry.getEntryId(), source.sourceUri(),
                    source.sourceRevision(), source.sourceManifestPath(),
                    source.sourceRetrievedAtEpochMs(), source.isEmpty()));
            DetectionCatalogSelection selection = selections.get(entry.getEntryId());
            if (selection == null || !selection.getEnabled()) continue;
            selectedEntries++;
            DetectionRule rule = catalogRule(entry, selection);
            rules.add(rule);
            increment(categoryCounts, entry.getCategory());
        }

        for (DispositionRuleConfiguration configured : configuration.getRulesList()) {
            rules.add(canonicalManualRule(configured));
        }
        rules.sort(Comparator.comparing(DetectionRule::getRuleId));
        Set<String> ruleIds = new HashSet<>();
        int expandedRules = 0;
        for (DetectionRule rule : rules) {
            if (!ruleIds.add(rule.getRuleId())) {
                throw failure("duplicate merged disposition rule id: " + rule.getRuleId());
            }
            expandedRules = Math.addExact(expandedRules, scopeVariants(rule.getScope()));
            if (expandedRules > MAX_COMPILED_RULES) {
                throw failure("compiled disposition rule budget exceeded");
            }
            increment(actionCounts, action(rule.getDefaultAction()));
        }
        List<String> warnings = new ArrayList<>();
        if (selectedEntries < entries.size()) warnings.add("UNSELECTED_CATALOG_ENTRY");
        return new CompiledDispositionConfiguration(
                List.copyOf(rules),
                new DispositionCatalogPreview(
                        entries.size(), selectedEntries, expandedRules,
                        categoryCounts, actionCounts, warnings, sourceSummaries));
    }

    private static DetectionRule catalogRule(
            DetectionCatalogEntry entry, DetectionCatalogSelection selection) {
        com.ellan.mcace.core.disposition.DispositionAction finalAction = action(selection.getFinalAction());
        DetectionSelector selector = canonicalSelector(entry);
        validateSelectorAction(selector, finalAction, false, entry.getEntryId());
        if ((entry.getCategory() == DetectionCatalogCategory.ACCESSIBILITY
                || entry.getCategory() == DetectionCatalogCategory.UTILITY)
                && finalAction != com.ellan.mcace.core.disposition.DispositionAction.ALLOW
                && finalAction != com.ellan.mcace.core.disposition.DispositionAction.OBSERVE) {
            throw failure("accessibility and utility catalog entries may only ALLOW or OBSERVE: "
                    + entry.getEntryId());
        }
        String ruleId = "catalog." + entry.getEntryId();
        if (ruleId.length() > MAX_IDENTIFIER_CHARS) throw failure("catalog rule id is too long");
        return DetectionRule.newBuilder()
                .setRuleId(ruleId)
                .setPriority(selection.getPriority())
                .setSelector(selector)
                .setConfidence(entry.getConfidence())
                .setDefaultAction(selection.getFinalAction())
                .setScope(entry.getScope())
                .setPlayerMessageKey(entry.getPlayerMessageKey())
                .setFalsePositiveNotes(entry.getFalsePositiveNotes())
                .setOperatorReason(entry.getOperatorReason())
                .setRevision(1)
                .setSourceId(entry.getSourceId())
                .setSourceSummary(entry.getSourceSummary())
                .setCatalogEntryId(entry.getEntryId())
                .setCatalogCategory(entry.getCategory())
                .setLimitJustification(entry.getLimitJustification())
                .setSourceUri(entry.getSourceUri())
                .setSourceRevision(entry.getSourceRevision())
                .setSourceManifestPath(entry.getSourceManifestPath())
                .setSourceRetrievedAtEpochMs(entry.getSourceRetrievedAtEpochMs())
                .build();
    }

    private static DetectionRule canonicalManualRule(DispositionRuleConfiguration configured) {
        DetectionRule rule = configured.getRule();
        if (rule.getIntroducedAtEpochMs() != 0 || rule.getEffectiveFromEpochMs() != 0
                || rule.getExpiresAtEpochMs() != 0) {
            throw failure("manual rule timestamps must be zero: " + rule.getRuleId());
        }
        if (!rule.getCatalogEntryId().isEmpty()
                || rule.getCatalogCategory() != DetectionCatalogCategory.DETECTION_CATALOG_CATEGORY_UNSPECIFIED) {
            throw failure("manual rules cannot forge catalog provenance: " + rule.getRuleId());
        }
        if (!CatalogSourceProvenance.from(rule).isEmpty()) {
            throw failure("manual rules cannot forge catalog source provenance: " + rule.getRuleId());
        }
        validateKnownRuleEnums(rule);
        DetectionSelector selector = canonicalSelector(configured);
        validateSelectorAction(selector, action(rule.getDefaultAction()), rule.getFoundationSecurity(), rule.getRuleId());
        return rule.toBuilder().setSelector(selector).build();
    }

    private static void validateSelectorAction(
            DetectionSelector selector, com.ellan.mcace.core.disposition.DispositionAction action,
            boolean foundationSecurity, String id) {
        try {
            DispositionSelectorActionPolicy.validate(
                    DispositionPolicyCompiler.selector(selector), action, foundationSecurity);
        } catch (RuntimeException exception) {
            throw failure("selector/action combination is unsafe: " + id + " (" + exception.getMessage() + ")");
        }
    }

    private static DetectionSelector canonicalSelector(DetectionCatalogEntry entry) {
        DetectionSelector selector = entry.getSelector();
        validateRawHashBytes(selector, entry.getEntryId());
        DetectionSelector.Builder builder = selector.toBuilder().clearSha256().clearContentRootSha256();
        switch (selector.getMatchType()) {
            case DETECTION_MATCH_EXACT_SHA256 -> {
                if (entry.getSha256Hex().isEmpty() || !entry.getContentRootSha256Hex().isEmpty()) {
                    throw failure("exact selector must use only sha256_hex: " + entry.getEntryId());
                }
                builder.setSha256(ByteString.copyFrom(parseHash(entry.getSha256Hex(), "sha256_hex")));
            }
            case DETECTION_MATCH_CONTENT_ROOT -> {
                if (entry.getContentRootSha256Hex().isEmpty() || !entry.getSha256Hex().isEmpty()) {
                    throw failure("content-root selector must use only content_root_sha256_hex: "
                            + entry.getEntryId());
                }
                builder.setContentRootSha256(ByteString.copyFrom(
                        parseHash(entry.getContentRootSha256Hex(), "content_root_sha256_hex")));
            }
            default -> {
                if (!entry.getSha256Hex().isEmpty() || !entry.getContentRootSha256Hex().isEmpty()) {
                    throw failure("hash helper is invalid for catalog selector: " + entry.getEntryId());
                }
            }
        }
        return builder.build();
    }

    private static DetectionSelector canonicalSelector(DispositionRuleConfiguration configured) {
        DetectionSelector selector = configured.getRule().getSelector();
        validateRawHashBytes(selector, configured.getRule().getRuleId());
        DetectionSelector.Builder builder = selector.toBuilder().clearSha256().clearContentRootSha256();
        switch (selector.getMatchType()) {
            case DETECTION_MATCH_EXACT_SHA256 -> {
                if (configured.getSha256Hex().isEmpty() || !configured.getContentRootSha256Hex().isEmpty()) {
                    throw failure("exact selector must use only sha256_hex: " + configured.getRule().getRuleId());
                }
                builder.setSha256(ByteString.copyFrom(
                        parseHash(configured.getSha256Hex(), "sha256_hex")));
            }
            case DETECTION_MATCH_CONTENT_ROOT -> {
                if (configured.getContentRootSha256Hex().isEmpty() || !configured.getSha256Hex().isEmpty()) {
                    throw failure("content-root selector must use only content_root_sha256_hex: "
                            + configured.getRule().getRuleId());
                }
                builder.setContentRootSha256(ByteString.copyFrom(
                        parseHash(configured.getContentRootSha256Hex(), "content_root_sha256_hex")));
            }
            default -> {
                if (!configured.getSha256Hex().isEmpty() || !configured.getContentRootSha256Hex().isEmpty()) {
                    throw failure("hash helper is invalid for manual selector: " + configured.getRule().getRuleId());
                }
            }
        }
        return builder.build();
    }

    private static void validateEntry(DetectionCatalogEntry entry) {
        requireIdentifier(entry.getEntryId(), "catalog entry id");
        switch (entry.getCategory()) {
            case CHEAT_MOD, XRAY_RESOURCE_PACK, AUTOMATION, SUSPICIOUS_CONFIG, ACCESSIBILITY, UTILITY -> { }
            case DETECTION_CATALOG_CATEGORY_UNSPECIFIED, UNRECOGNIZED ->
                    throw failure("unknown catalog category: " + entry.getEntryId());
        }
        validateKnownSelectorEnums(entry.getSelector(), entry.getEntryId());
        validateRawHashBytes(entry.getSelector(), entry.getEntryId());
        if (entry.getConfidence() == DetectionConfidence.DETECTION_CONFIDENCE_UNSPECIFIED
                || entry.getConfidence() == DetectionConfidence.UNRECOGNIZED
                || entry.getSuggestedAction() == DispositionAction.DISPOSITION_ACTION_UNSPECIFIED
                || entry.getSuggestedAction() == DispositionAction.UNRECOGNIZED) {
            throw failure("catalog confidence or suggestion is unspecified: " + entry.getEntryId());
        }
        try {
            CatalogSourceProvenance.from(entry).validate();
        } catch (IllegalArgumentException exception) {
            throw failure("catalog source provenance is invalid: " + entry.getEntryId()
                    + " (" + exception.getMessage() + ")");
        }
        if ((entry.getCategory() == DetectionCatalogCategory.ACCESSIBILITY
                || entry.getCategory() == DetectionCatalogCategory.UTILITY)
                && entry.getSuggestedAction().getNumber() > DispositionAction.DISPOSITION_OBSERVE.getNumber()) {
            throw failure("accessibility and utility suggestions may only ALLOW or OBSERVE: " + entry.getEntryId());
        }
        requireText(entry.getPlayerMessageKey(), "catalog player message key");
        requireText(entry.getOperatorReason(), "catalog operator reason");
        requireText(entry.getFalsePositiveNotes(), "catalog false-positive notes");
        requireIdentifier(entry.getSourceId(), "catalog source id");
        requireText(entry.getSourceSummary(), "catalog source summary");
        if (entry.getScope().getPlayerIdsCount() != 0) {
            throw failure("catalog entries cannot use player scope: " + entry.getEntryId());
        }
        validateScopeDuplicates(entry.getScope(), entry.getEntryId());
        canonicalSelector(entry);
    }

    private static void validateSelection(DetectionCatalogSelection selection) {
        requireIdentifier(selection.getEntryId(), "catalog selection entry id");
        if (selection.getEnabled()
                && (selection.getFinalAction() == DispositionAction.DISPOSITION_ACTION_UNSPECIFIED
                || selection.getFinalAction() == DispositionAction.UNRECOGNIZED)) {
            throw failure("enabled catalog selection needs an explicit final action: " + selection.getEntryId());
        }
        if (!selection.getEnabled() && selection.getFinalAction() != DispositionAction.DISPOSITION_ACTION_UNSPECIFIED) {
            throw failure("disabled catalog selection must not carry a final action: " + selection.getEntryId());
        }
    }

    private static void validateKnownRuleEnums(DetectionRule rule) {
        validateKnownSelectorEnums(rule.getSelector(), rule.getRuleId());
        if (rule.getConfidence() == DetectionConfidence.DETECTION_CONFIDENCE_UNSPECIFIED
                || rule.getConfidence() == DetectionConfidence.UNRECOGNIZED
                || rule.getDefaultAction() == DispositionAction.DISPOSITION_ACTION_UNSPECIFIED
                || rule.getDefaultAction() == DispositionAction.UNRECOGNIZED) {
            throw failure("manual rule action or confidence is unspecified: " + rule.getRuleId());
        }
    }

    private static void validateKnownSelectorEnums(DetectionSelector selector, String id) {
        if (selector.getArtifactType() == DetectionArtifactType.DETECTION_ARTIFACT_TYPE_UNSPECIFIED
                || selector.getArtifactType() == DetectionArtifactType.UNRECOGNIZED
                || selector.getMatchType() == DetectionMatchType.DETECTION_MATCH_TYPE_UNSPECIFIED
                || selector.getMatchType() == DetectionMatchType.UNRECOGNIZED) {
            throw failure("catalog selector enum is unspecified: " + id);
        }
    }

    private static void validateRawHashBytes(DetectionSelector selector, String id) {
        if (!selector.getSha256().isEmpty() || !selector.getContentRootSha256().isEmpty()) {
            throw failure("raw hash bytes are not allowed in administrator catalog input: " + id);
        }
    }

    private static void validateScopeDuplicates(DetectionRuleScope scope, String id) {
        validateUnique(scope.getProxyIdsList(), "proxy", id);
        validateUnique(scope.getBackendIdsList(), "backend", id);
        validateUnique(scope.getGameModesList(), "game mode", id);
        validateUnique(scope.getPermissionGroupsList(), "permission", id);
        validateUnique(scope.getWorldIdsList(), "world", id);
    }

    private static void validateUnique(List<String> values, String name, String id) {
        if (values.stream().anyMatch(value -> value.isBlank() || value.length() > MAX_IDENTIFIER_CHARS
                || value.chars().anyMatch(Character::isISOControl))) {
            throw failure("invalid " + name + " scope in catalog entry: " + id);
        }
        if (new HashSet<>(values).size() != values.size()) {
            throw failure("duplicate " + name + " scope in catalog entry: " + id);
        }
    }

    private static int scopeVariants(DetectionRuleScope scope) {
        long result = 1;
        for (List<String> values : List.of(scope.getProxyIdsList(), scope.getBackendIdsList(),
                scope.getGameModesList(), scope.getPermissionGroupsList(), scope.getWorldIdsList(),
                scope.getPlayerIdsList())) {
            try {
                result = Math.multiplyExact(result, values.isEmpty() ? 1 : values.size());
            } catch (ArithmeticException exception) {
                throw failure("scope expansion exceeds rule budget");
            }
            if (result > MAX_COMPILED_RULES) throw failure("scope expansion exceeds rule budget");
        }
        return (int) result;
    }

    private static byte[] parseHash(String value, String field) {
        if (value == null || value.length() != 64) throw failure(field + " must be exactly 64 hex characters");
        try {
            return HexFormat.of().parseHex(value);
        } catch (IllegalArgumentException exception) {
            throw failure(field + " must be exactly 64 hex characters");
        }
    }

    private static void requireIdentifier(String value, String name) {
        if (value == null || value.isBlank() || value.length() > MAX_IDENTIFIER_CHARS
                || value.chars().anyMatch(Character::isISOControl)) {
            throw failure(name + " is missing or outside bounds");
        }
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank() || value.length() > MAX_TEXT_CHARS
                || value.chars().anyMatch(Character::isISOControl)) {
            throw failure(name + " is missing or outside bounds");
        }
    }

    private static <K> void increment(Map<K, Integer> values, K key) {
        values.merge(key, 1, Integer::sum);
    }

    private static com.ellan.mcace.core.disposition.DispositionAction action(DispositionAction action) {
        return switch (action) {
            case DISPOSITION_ALLOW -> com.ellan.mcace.core.disposition.DispositionAction.ALLOW;
            case DISPOSITION_OBSERVE -> com.ellan.mcace.core.disposition.DispositionAction.OBSERVE;
            case DISPOSITION_NOTICE -> com.ellan.mcace.core.disposition.DispositionAction.NOTICE;
            case DISPOSITION_WARN -> com.ellan.mcace.core.disposition.DispositionAction.WARN;
            case DISPOSITION_CHALLENGE -> com.ellan.mcace.core.disposition.DispositionAction.CHALLENGE;
            case DISPOSITION_LIMIT -> com.ellan.mcace.core.disposition.DispositionAction.LIMIT;
            case DISPOSITION_QUARANTINE -> com.ellan.mcace.core.disposition.DispositionAction.QUARANTINE;
            case DISPOSITION_DENY -> com.ellan.mcace.core.disposition.DispositionAction.DENY;
            case DISPOSITION_ACTION_UNSPECIFIED, UNRECOGNIZED -> throw failure("unknown disposition action");
        };
    }

    private static IllegalArgumentException failure(String message) {
        return new IllegalArgumentException(message);
    }

    public record CompiledDispositionConfiguration(
            List<DetectionRule> rules, DispositionCatalogPreview preview) {
        public CompiledDispositionConfiguration {
            rules = List.copyOf(rules);
            if (preview == null) throw new NullPointerException("preview");
        }
    }
}
