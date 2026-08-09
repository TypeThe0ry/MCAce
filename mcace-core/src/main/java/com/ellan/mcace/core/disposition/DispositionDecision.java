package com.ellan.mcace.core.disposition;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record DispositionDecision(ArtifactObservation observation, DispositionAction action, Optional<String> winningRuleId,
                                  List<RuleMatchExplanation> explanations) {
    public DispositionDecision { Objects.requireNonNull(observation, "observation"); Objects.requireNonNull(action, "action"); Objects.requireNonNull(winningRuleId, "winningRuleId"); Objects.requireNonNull(explanations, "explanations"); explanations = List.copyOf(explanations); }
}
