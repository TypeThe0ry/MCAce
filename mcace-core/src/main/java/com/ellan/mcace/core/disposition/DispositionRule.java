package com.ellan.mcace.core.disposition;

import java.time.Instant;
import java.util.Objects;

public record DispositionRule(String ruleId, ArtifactSelector selector, RuleScope scope, DispositionAction action,
                              Confidence minimumConfidence, Instant effectiveFrom, Instant expiresAt, int priority,
                              boolean foundationSecurity, RuleExplanation explanation, boolean disabled) {
    /** Compatibility constructor for locally-authored rules without signed policy provenance. */
    public DispositionRule(String ruleId, ArtifactSelector selector, RuleScope scope, DispositionAction action,
                           Confidence minimumConfidence, Instant effectiveFrom, Instant expiresAt, int priority,
                           boolean foundationSecurity) {
        this(ruleId, selector, scope, action, minimumConfidence, effectiveFrom, expiresAt, priority,
                foundationSecurity, null, false);
    }
    public DispositionRule {
        Objects.requireNonNull(ruleId, "ruleId"); Objects.requireNonNull(selector, "selector"); Objects.requireNonNull(scope, "scope"); Objects.requireNonNull(action, "action"); Objects.requireNonNull(minimumConfidence, "minimumConfidence");
        if (ruleId.isBlank()) throw new IllegalArgumentException("ruleId must not be blank");
        if (expiresAt != null && effectiveFrom != null && !expiresAt.isAfter(effectiveFrom)) throw new IllegalArgumentException("expiresAt must be after effectiveFrom");
        if (foundationSecurity && action == DispositionAction.ALLOW) throw new IllegalArgumentException("foundation security rules cannot allow");
        if (foundationSecurity && selector.type() != ArtifactType.PROTOCOL) {
            throw new IllegalArgumentException("foundation security rules must select protocol artifacts");
        }
        DispositionSelectorActionPolicy.validate(selector, action, foundationSecurity);
    }
    public boolean activeAt(Instant time) { return !disabled && (effectiveFrom == null || !time.isBefore(effectiveFrom)) && (expiresAt == null || time.isBefore(expiresAt)); }
}
