package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.EvaluationContext;

/** Common runtime evaluation boundary. Implementations must not apply admission or punishment. */
@FunctionalInterface
public interface ArtifactObservationEvaluator {
    ProxyPolicyEvaluation evaluate(EvaluationContext context, ArtifactObservation observation);
}
