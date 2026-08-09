package com.ellan.mcace.core.disposition;

import java.util.Objects;

/** A complete per-rule audit record, including non-matches. */
public record RuleMatchExplanation(String ruleId, boolean active, boolean scopeMatched, boolean selectorMatched,
                                   boolean confidenceMatched, boolean selected, String outcome) {
    public RuleMatchExplanation { Objects.requireNonNull(ruleId, "ruleId"); Objects.requireNonNull(outcome, "outcome"); }
}
