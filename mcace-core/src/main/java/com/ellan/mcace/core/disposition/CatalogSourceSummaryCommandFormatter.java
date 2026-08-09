package com.ellan.mcace.core.disposition;

import java.net.URI;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/** Formats bounded, source-only catalog details for administrative command output. */
public final class CatalogSourceSummaryCommandFormatter {
    public static final int MAX_LISTED_SOURCES = 8;
    private static final int MAX_DISPLAY_URI_CHARS = 512;

    private CatalogSourceSummaryCommandFormatter() {
    }

    /**
     * Returns at most eight sanitized source entries followed, when needed, by one truncation line.
     * Query strings are intentionally dropped so command output cannot disclose URL credentials.
     */
    public static List<String> render(List<DispositionCatalogSourceSummary> summaries) {
        Objects.requireNonNull(summaries, "summaries");
        List<DispositionCatalogSourceSummary> ordered = summaries.stream()
                .sorted(Comparator.comparing(DispositionCatalogSourceSummary::entryId))
                .toList();
        List<String> output = ordered.stream()
                .limit(MAX_LISTED_SOURCES)
                .map(CatalogSourceSummaryCommandFormatter::render)
                .collect(java.util.stream.Collectors.toCollection(java.util.ArrayList::new));
        if (ordered.size() > MAX_LISTED_SOURCES) {
            output.add("MCAce: catalog source entries-truncated=" + (ordered.size() - MAX_LISTED_SOURCES));
        }
        return List.copyOf(output);
    }

    private static String render(DispositionCatalogSourceSummary summary) {
        if (summary.legacy()) {
            return "MCAce: catalog source entry=" + safeEntryId(summary.entryId())
                    + " provenance=legacy";
        }
        return "MCAce: catalog source entry=" + safeEntryId(summary.entryId())
                + " source-uri=" + safeHttpsUri(summary.sourceUri())
                + " source-revision=" + safeRepositoryValue(summary.sourceRevision())
                + " source-manifest-path=" + safeRepositoryValue(summary.sourceManifestPath())
                + " source-retrieved-at=" + summary.retrievedAtEpochMs()
                + "/" + DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(summary.retrievedAtEpochMs()))
                + " provenance=identity-only";
    }

    private static String safeEntryId(String value) {
        return value != null && value.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,127}") ? value : "unavailable";
    }

    private static String safeRepositoryValue(String value) {
        return value != null && value.length() <= 512 && value.matches("[A-Za-z0-9][A-Za-z0-9._/-]*")
                ? value : "unavailable";
    }

    private static String safeHttpsUri(String value) {
        try {
            URI uri = URI.create(value);
            String host = uri.getHost();
            if (!"https".equalsIgnoreCase(uri.getScheme()) || host == null
                    || !host.matches("[A-Za-z0-9.-]+") || uri.getPort() < -1) {
                return "unavailable";
            }
            String path = uri.getRawPath();
            if (path == null || !path.matches("/[A-Za-z0-9._~/%-]*")) return "unavailable";
            String rendered = "https://" + host.toLowerCase(Locale.ROOT)
                    + (uri.getPort() == -1 ? "" : ":" + uri.getPort()) + path;
            return rendered.length() <= MAX_DISPLAY_URI_CHARS
                    ? rendered : "https://" + host.toLowerCase(Locale.ROOT) + "/<truncated>";
        } catch (IllegalArgumentException exception) {
            return "unavailable";
        }
    }
}
