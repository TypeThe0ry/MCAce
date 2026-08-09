package com.ellan.mcace.core.federation;

import java.util.Objects;
import java.util.Optional;

/** Target-side result. OBSERVED is explicitly advisory and has no admission side effect. */
public record FederationPresentationResult(
        FederationRuntimeStatus status,
        Optional<FederationObservation> observation) {
    public FederationPresentationResult {
        Objects.requireNonNull(status, "status");
        observation = Objects.requireNonNull(observation, "observation");
        if ((status == FederationRuntimeStatus.OBSERVED) != observation.isPresent()) {
            throw new IllegalArgumentException("inconsistent federation presentation result");
        }
    }

    public static FederationPresentationResult rejected(FederationRuntimeStatus status) {
        return new FederationPresentationResult(status, Optional.empty());
    }
}
