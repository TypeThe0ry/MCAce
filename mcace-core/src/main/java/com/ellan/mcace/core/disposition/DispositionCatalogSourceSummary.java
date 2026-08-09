package com.ellan.mcace.core.disposition;

import java.util.Objects;

/** Bounded provenance view for administrative catalog listing; it contains no artifact content. */
public record DispositionCatalogSourceSummary(
        String entryId, String sourceUri, String sourceRevision, String sourceManifestPath,
        long retrievedAtEpochMs, boolean legacy) {
    public DispositionCatalogSourceSummary {
        Objects.requireNonNull(entryId, "entryId");
        if (entryId.isBlank() || entryId.length() > 128
                || entryId.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("catalog source summary entry id is outside bounds");
        }
        CatalogSourceProvenance provenance = new CatalogSourceProvenance(
                sourceUri, sourceRevision, sourceManifestPath, retrievedAtEpochMs);
        provenance.validate();
        if (legacy != provenance.isEmpty()) {
            throw new IllegalArgumentException("catalog source summary legacy marker does not match provenance");
        }
    }
}
