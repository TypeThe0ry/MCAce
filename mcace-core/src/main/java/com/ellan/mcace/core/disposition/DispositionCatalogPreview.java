package com.ellan.mcace.core.disposition;

import com.ellan.mcace.protocol.generated.DetectionCatalogCategory;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.HashSet;

/** Content-free preview of an unsigned catalog merge. */
public record DispositionCatalogPreview(
        int catalogEntryCount,
        int selectedEntryCount,
        int compiledRuleCount,
        Map<DetectionCatalogCategory, Integer> categoryCounts,
        Map<DispositionAction, Integer> actionCounts,
        List<String> warnings,
        List<DispositionCatalogSourceSummary> sourceSummaries) {
    /** Compatibility constructor for callers that do not request catalog source metadata. */
    public DispositionCatalogPreview(int catalogEntryCount, int selectedEntryCount, int compiledRuleCount,
                                     Map<DetectionCatalogCategory, Integer> categoryCounts,
                                     Map<DispositionAction, Integer> actionCounts, List<String> warnings) {
        this(catalogEntryCount, selectedEntryCount, compiledRuleCount, categoryCounts, actionCounts,
                warnings, List.of());
    }

    public DispositionCatalogPreview {
        if (catalogEntryCount < 0 || selectedEntryCount < 0 || compiledRuleCount < 0) {
            throw new IllegalArgumentException("preview counts must not be negative");
        }
        categoryCounts = Map.copyOf(Objects.requireNonNull(categoryCounts, "categoryCounts"));
        actionCounts = Map.copyOf(Objects.requireNonNull(actionCounts, "actionCounts"));
        warnings = List.copyOf(Objects.requireNonNull(warnings, "warnings"));
        sourceSummaries = List.copyOf(Objects.requireNonNull(sourceSummaries, "sourceSummaries"));
        if (sourceSummaries.size() > catalogEntryCount || sourceSummaries.size()
                > DispositionPolicyConfigurationCompiler.MAX_CATALOG_ENTRIES
                || new HashSet<>(sourceSummaries.stream()
                .map(DispositionCatalogSourceSummary::entryId).toList()).size() != sourceSummaries.size()) {
            throw new IllegalArgumentException("catalog source summaries exceed bounds or contain duplicate entry ids");
        }
    }
}
