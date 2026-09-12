package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.Confidence;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import java.util.Objects;

/**
 * Authenticated handoff from a server-side behaviour adapter to the trusted disposition
 * boundary.  The adapter must first correlate the client observation with its own signal; raw
 * client evidence never enters the server-confirmed authorization entrypoint.
 */
public record ServerConfirmedDispositionInput(
        ServerBehaviorObservation serverObservation,
        ArtifactObservation correlatedObservation) {
    public ServerConfirmedDispositionInput {
        Objects.requireNonNull(serverObservation, "serverObservation");
        Objects.requireNonNull(correlatedObservation, "correlatedObservation");
        if (correlatedObservation.origin() != ObservationOrigin.SERVER_CONFIRMED
                || correlatedObservation.confidence() != Confidence.CONFIRMED) {
            throw new IllegalArgumentException(
                    "server-confirmed authorization requires correlated confirmed evidence");
        }
        if (!serverObservation.provider().equals(correlatedObservation.metadata().get("correlated_provider"))
                || !serverObservation.signal().equals(correlatedObservation.metadata().get("correlated_signal"))
                || !ObservationOrigin.CLIENT_REPORTED.name().equals(
                        correlatedObservation.metadata().get("client_origin"))) {
            throw new IllegalArgumentException(
                    "server-confirmed authorization requires correlator metadata");
        }
    }
}
