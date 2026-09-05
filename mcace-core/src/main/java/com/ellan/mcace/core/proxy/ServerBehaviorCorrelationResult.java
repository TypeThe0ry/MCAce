package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import java.util.Objects;
import java.util.Optional;

/** Bounded result of correlating a provider signal with a client artifact observation. */
public record ServerBehaviorCorrelationResult(
        ArtifactObservation correlatedObservation,
        ProxyPolicyEvaluation evaluation,
        Optional<AuthenticatedManifestDispositionEvent> authorizedEvent) {
    public ServerBehaviorCorrelationResult {
        Objects.requireNonNull(correlatedObservation, "correlatedObservation");
        Objects.requireNonNull(evaluation, "evaluation");
        Objects.requireNonNull(authorizedEvent, "authorizedEvent");
        if (correlatedObservation.origin() != com.ellan.mcace.core.disposition.ObservationOrigin.SERVER_CONFIRMED) {
            throw new IllegalArgumentException("correlation result must be server confirmed");
        }
        authorizedEvent.ifPresent(event -> {
            if (event.authorityOrigin() != com.ellan.mcace.core.disposition.ObservationOrigin.SERVER_CONFIRMED) {
                throw new IllegalArgumentException("correlation event must be server confirmed");
            }
        });
    }
}
