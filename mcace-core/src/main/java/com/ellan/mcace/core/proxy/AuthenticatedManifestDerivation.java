package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import java.util.List;
import java.util.Objects;

/** Complete server-side derivation; consistency issues never omit a manifest entry. */
public record AuthenticatedManifestDerivation(
        List<ArtifactObservation> observations, List<String> consistencyIssues) {
    public AuthenticatedManifestDerivation {
        Objects.requireNonNull(observations, "observations");
        Objects.requireNonNull(consistencyIssues, "consistencyIssues");
        observations = List.copyOf(observations);
        consistencyIssues = List.copyOf(consistencyIssues);
    }
}
