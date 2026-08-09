package com.ellan.mcace.core.disposition;

import java.util.Objects;

/** Human and operator-facing context retained from a signed rule for later review. */
public record RuleExplanation(String sourceRuleId, String playerMessageKey, String falsePositiveNotes, String operatorReason,
                              long revision, long introducedAtEpochMs, boolean exception, String sourceUri,
                              String sourceRevision, String sourceManifestPath, long sourceRetrievedAtEpochMs) {
    /** Compatibility constructor for legacy signed rules without catalog source provenance. */
    public RuleExplanation(String sourceRuleId, String playerMessageKey, String falsePositiveNotes,
                           String operatorReason, long revision, long introducedAtEpochMs, boolean exception) {
        this(sourceRuleId, playerMessageKey, falsePositiveNotes, operatorReason, revision,
                introducedAtEpochMs, exception, "", "", "", 0);
    }

    public RuleExplanation {
        Objects.requireNonNull(sourceRuleId, "sourceRuleId");
        Objects.requireNonNull(playerMessageKey, "playerMessageKey");
        Objects.requireNonNull(falsePositiveNotes, "falsePositiveNotes");
        Objects.requireNonNull(operatorReason, "operatorReason");
        if (sourceRuleId.isBlank() || revision <= 0 || introducedAtEpochMs <= 0) {
            throw new IllegalArgumentException("rule provenance must have a positive revision and introduction time");
        }
        new CatalogSourceProvenance(sourceUri, sourceRevision, sourceManifestPath,
                sourceRetrievedAtEpochMs).validate();
    }
}
