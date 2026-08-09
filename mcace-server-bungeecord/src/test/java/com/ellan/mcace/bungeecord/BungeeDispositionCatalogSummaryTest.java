package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.DispositionCatalogPreview;
import com.ellan.mcace.core.disposition.DispositionCatalogSourceSummary;
import com.ellan.mcace.protocol.generated.DetectionCatalogCategory;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

final class BungeeDispositionCatalogSummaryTest {
    @Test
    void rendersAccessibilityAndUtilityCountsWithoutPolicyMaterial() {
        String rendered = BungeeDispositionCatalogSummary.render(
                "preview",
                new DispositionCatalogPreview(
                        2, 2, 2,
                        Map.of(DetectionCatalogCategory.ACCESSIBILITY, 1,
                                DetectionCatalogCategory.UTILITY, 1),
                        Map.of(DispositionAction.ALLOW, 1, DispositionAction.OBSERVE, 1),
                        java.util.List.of("UNSELECTED_CATALOG_ENTRY")),
                Optional.of("https://example.invalid/catalog?hash=" + "0".repeat(64)),
                Optional.of(7L), BungeeDispositionExecutionMode.MONITOR);

        assertTrue(rendered.contains("ACCESSIBILITY:1"));
        assertTrue(rendered.contains("UTILITY:1"));
        assertTrue(rendered.contains("ALLOW:1"));
        assertTrue(rendered.contains("OBSERVE:1"));
        assertTrue(rendered.contains("UNSELECTED_CATALOG_ENTRY"));
        assertTrue(rendered.contains("active-sequence=7"));
        assertTrue(rendered.contains("version=unavailable"));
        assertTrue(rendered.contains("high-impact=LIMITED_ROUTE_REQUIRED"));
        assertTrue(rendered.contains("command-mode-unchanged=true"));
        assertTrue(Set.of("/", "\\", "http", "https").stream().noneMatch(rendered::contains));
        assertTrue(!rendered.contains("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    }

    @Test
    void listRendersOnlyBoundedSanitizedSourceProvenance() {
        List<String> rendered = BungeeDispositionCatalogSummary.listSources(previewWithSources());

        assertEquals(9, rendered.size(), "eight sources plus one truncation marker");
        assertTrue(rendered.get(0).contains("entry=entry-0"));
        assertTrue(rendered.get(0).contains("source-uri=https://catalog.example/manifest/0"));
        assertTrue(rendered.get(0).contains("source-revision=revision-0"));
        assertTrue(rendered.get(0).contains("source-manifest-path=src/main/resources/fabric.mod.json"));
        assertTrue(rendered.get(0).contains("source-retrieved-at=1786204800000/2026-08-08T16:00:00Z"));
        assertTrue(rendered.stream().anyMatch(line -> line.contains("entry=legacy-entry provenance=legacy")));
        assertEquals("MCAce: catalog source entries-truncated=1", rendered.get(8));
        assertFalse(rendered.stream().anyMatch(line -> line.contains("token") || line.contains("?")
                || line.contains("secret") || line.contains("0123456789abcdef0123456789abcdef")));
    }

    private static DispositionCatalogPreview previewWithSources() {
        List<DispositionCatalogSourceSummary> summaries = new ArrayList<>();
        for (int index = 0; index < 7; index++) {
            summaries.add(new DispositionCatalogSourceSummary(
                    "entry-" + index,
                    "https://catalog.example/manifest/" + index + "?token=secret",
                    "revision-" + index,
                    "src/main/resources/fabric.mod.json",
                    1_786_204_800_000L,
                    false));
        }
        summaries.add(new DispositionCatalogSourceSummary("legacy-entry", "", "", "", 0, true));
        summaries.add(new DispositionCatalogSourceSummary(
                "z-extra", "https://catalog.example/manifest/z?token=secret", "revision-z",
                "src/main/resources/fabric.mod.json", 1_786_204_800_000L, false));
        return new DispositionCatalogPreview(
                summaries.size(), 0, 0, Map.of(), Map.of(), List.of(), summaries);
    }
}
