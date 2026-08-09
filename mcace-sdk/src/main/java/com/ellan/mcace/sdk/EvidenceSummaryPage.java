package com.ellan.mcace.sdk;

import java.util.List;
import java.util.Objects;

/**
 * Immutable, content-free response from the optional evidence-summary capability.
 *
 * @param availability availability or authorization outcome
 * @param summaries immutable evidence metadata, never raw evidence
 * @since 1.0
 */
public record EvidenceSummaryPage(EvidenceSummaryAvailability availability, List<EvidenceSummary> summaries) {
    /** Creates a validated immutable evidence-summary page. */
    public EvidenceSummaryPage {
        Objects.requireNonNull(availability, "availability");
        summaries = List.copyOf(Objects.requireNonNull(summaries, "summaries"));
        SdkValidation.boundedSize(summaries, "summaries");
        if (availability != EvidenceSummaryAvailability.AVAILABLE && !summaries.isEmpty()) {
            throw new IllegalArgumentException("unavailable evidence pages must not contain summaries");
        }
    }

    /**
     * Returns the explicit default result for an implementation that does not offer evidence summaries.
     *
     * @return empty not-supported page
     */
    public static EvidenceSummaryPage notSupported() {
        return new EvidenceSummaryPage(EvidenceSummaryAvailability.NOT_SUPPORTED, List.of());
    }
}
