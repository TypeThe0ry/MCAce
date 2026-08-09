package com.ellan.mcace.core.disposition;

import com.ellan.mcace.protocol.generated.DetectionCatalogEntry;
import com.ellan.mcace.protocol.generated.DetectionRule;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;

/**
 * Bounded, review-only source provenance for a catalog identity.
 *
 * <p>All four fields are deliberately all-or-nothing so a signed rule never appears sourced
 * while omitting the immutable revision, repository path, or retrieval time needed to review it.
 * This metadata is not evidence of an artifact match and has no enforcement authority.</p>
 */
public record CatalogSourceProvenance(
        String sourceUri, String sourceRevision, String sourceManifestPath,
        long sourceRetrievedAtEpochMs) {
    public static final int MAX_SOURCE_URI_CHARS = 2_048;
    public static final int MAX_SOURCE_REVISION_CHARS = 128;
    public static final int MAX_SOURCE_MANIFEST_PATH_CHARS = 512;

    public CatalogSourceProvenance {
        sourceUri = Objects.requireNonNull(sourceUri, "sourceUri");
        sourceRevision = Objects.requireNonNull(sourceRevision, "sourceRevision");
        sourceManifestPath = Objects.requireNonNull(sourceManifestPath, "sourceManifestPath");
    }

    public static CatalogSourceProvenance from(DetectionCatalogEntry entry) {
        Objects.requireNonNull(entry, "entry");
        return new CatalogSourceProvenance(entry.getSourceUri(), entry.getSourceRevision(),
                entry.getSourceManifestPath(), entry.getSourceRetrievedAtEpochMs());
    }

    public static CatalogSourceProvenance from(DetectionRule rule) {
        Objects.requireNonNull(rule, "rule");
        return new CatalogSourceProvenance(rule.getSourceUri(), rule.getSourceRevision(),
                rule.getSourceManifestPath(), rule.getSourceRetrievedAtEpochMs());
    }

    public boolean isEmpty() {
        return sourceUri.isEmpty() && sourceRevision.isEmpty() && sourceManifestPath.isEmpty()
                && sourceRetrievedAtEpochMs == 0;
    }

    /** Validates local input structure without requiring a publisher clock. */
    public void validate() {
        if (isEmpty()) return;
        if (sourceUri.isEmpty() || sourceRevision.isEmpty() || sourceManifestPath.isEmpty()
                || sourceRetrievedAtEpochMs <= 0) {
            throw new IllegalArgumentException("catalog source provenance must be all present or all absent");
        }
        validateHttpsUri(sourceUri);
        validateRevision(sourceRevision);
        validateManifestPath(sourceManifestPath);
    }

    /** Publisher-time gate: future retrieval claims must never enter a newly issued rule. */
    public void validateRetrievedNotAfter(long issuedAtEpochMs) {
        validate();
        if (!isEmpty() && sourceRetrievedAtEpochMs > issuedAtEpochMs) {
            throw new IllegalArgumentException("catalog source retrieval time is after policy issuance");
        }
    }

    private static void validateHttpsUri(String value) {
        if (value.length() > MAX_SOURCE_URI_CHARS || containsControl(value)) {
            throw new IllegalArgumentException("catalog source URI is outside bounds");
        }
        try {
            URI uri = new URI(value);
            if (!uri.isAbsolute() || !"https".equalsIgnoreCase(uri.getScheme())
                    || uri.getHost() == null || uri.getHost().isBlank()
                    || uri.getRawUserInfo() != null || uri.getRawFragment() != null) {
                throw new IllegalArgumentException("catalog source URI must be absolute HTTPS without userinfo or fragment");
            }
        } catch (URISyntaxException exception) {
            throw new IllegalArgumentException("catalog source URI is invalid", exception);
        }
    }

    private static void validateRevision(String value) {
        if (value.length() > MAX_SOURCE_REVISION_CHARS
                || !value.matches("[A-Za-z0-9][A-Za-z0-9._-]*")) {
            throw new IllegalArgumentException("catalog source revision is outside safe bounds");
        }
    }

    private static void validateManifestPath(String value) {
        if (value.length() > MAX_SOURCE_MANIFEST_PATH_CHARS || value.startsWith("/")
                || value.endsWith("/") || value.indexOf('\\') >= 0 || !safeRepositoryToken(value)) {
            throw new IllegalArgumentException("catalog source manifest path is outside safe bounds");
        }
    }

    private static boolean safeRepositoryToken(String value) {
        if (value.isEmpty() || containsControl(value) || value.startsWith("/") || value.endsWith("/")
                || value.contains("//")) return false;
        for (String segment : value.split("/", -1)) {
            if (segment.isEmpty() || segment.equals(".") || segment.equals("..")
                    || !segment.matches("[A-Za-z0-9][A-Za-z0-9._-]*")) return false;
        }
        return true;
    }

    private static boolean containsControl(String value) {
        return value.chars().anyMatch(Character::isISOControl);
    }
}
