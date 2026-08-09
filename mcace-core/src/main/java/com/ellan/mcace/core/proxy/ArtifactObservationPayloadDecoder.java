package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import java.util.List;

/** Protocol adapters decode a completed bounded payload into neutral observations. */
@FunctionalInterface
public interface ArtifactObservationPayloadDecoder {
    List<ArtifactObservation> decode(byte[] payload) throws ObservationPayloadException;
}
