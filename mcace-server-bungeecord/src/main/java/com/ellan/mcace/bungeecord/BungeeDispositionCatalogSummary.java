package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.disposition.CatalogSourceSummaryCommandFormatter;
import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.DispositionCatalogPreview;
import com.ellan.mcace.protocol.generated.DetectionCatalogCategory;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/** Formats only bounded catalog diagnostics; it never exposes policy material. */
final class BungeeDispositionCatalogSummary {
    private BungeeDispositionCatalogSummary() {
    }

    static String render(
            String operation,
            DispositionCatalogPreview preview,
            Optional<String> version,
            Optional<Long> activeSequence,
            BungeeDispositionExecutionMode mode) {
        return "MCAce: disposition catalog " + operation
                + " version=" + safeVersion(version)
                + " entries=" + preview.catalogEntryCount()
                + " selected=" + preview.selectedEntryCount()
                + " rules=" + preview.compiledRuleCount()
                + " categories=" + counts(preview.categoryCounts(), DetectionCatalogCategory::name)
                + " actions=" + counts(preview.actionCounts(), DispositionAction::name)
                + " warnings=" + warnings(preview.warnings())
                + " active-sequence=" + activeSequence.map(String::valueOf).orElse("none")
                + " mode=" + mode.name()
                + " high-impact=LIMITED_ROUTE_REQUIRED"
                + " command-mode-unchanged=true";
    }

    static String failure(Optional<Long> activeSequence, BungeeDispositionExecutionMode mode) {
        return "MCAce: disposition catalog publish failed; active policy unchanged"
                + " warnings=VALIDATION_FAILED"
                + " active-sequence=" + activeSequence.map(String::valueOf).orElse("none")
                + " mode=" + mode.name()
                + " high-impact=LIMITED_ROUTE_REQUIRED"
                + " command-mode-unchanged=true";
    }

    static List<String> listSources(DispositionCatalogPreview preview) {
        return CatalogSourceSummaryCommandFormatter.render(preview.sourceSummaries());
    }

    static String safeVersion(Optional<String> version) {
        return version.filter(value -> value.matches("[A-Za-z0-9._-]{1,64}")).orElse("unavailable");
    }

    private static <T> String counts(Map<T, Integer> values, Function<T, String> name) {
        List<String> entries = new ArrayList<>();
        values.entrySet().stream()
                .filter(entry -> entry.getValue() != null && entry.getValue() > 0)
                .sorted(Map.Entry.comparingByKey((left, right) -> name.apply(left).compareTo(name.apply(right))))
                .forEach(entry -> entries.add(name.apply(entry.getKey()) + ":" + entry.getValue()));
        return entries.isEmpty() ? "none" : String.join(",", entries);
    }

    private static String warnings(List<String> values) {
        List<String> codes = values.stream()
                .map(value -> value != null && value.matches("[A-Z0-9_]+") ? value : "INVALID_WARNING_CODE")
                .distinct()
                .sorted()
                .toList();
        return codes.isEmpty() ? "none" : String.join(",", codes);
    }
}
