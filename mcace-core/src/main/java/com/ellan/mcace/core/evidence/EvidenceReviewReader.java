package com.ellan.mcace.core.evidence;

import java.util.Optional;
import java.util.UUID;

/** Narrow raw-evidence read boundary used only by the opt-in local review service. */
@FunctionalInterface
public interface EvidenceReviewReader {
    Optional<EvidenceReviewArtifact> readForReview(UUID evidenceId) throws Exception;

    static EvidenceReviewReader disabled() {
        return ignored -> Optional.empty();
    }
}
