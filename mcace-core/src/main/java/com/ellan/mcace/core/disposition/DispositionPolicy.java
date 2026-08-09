package com.ellan.mcace.core.disposition;

import java.util.List;
import java.util.Objects;
import java.util.Set;

public record DispositionPolicy(String version, List<DispositionRule> rules, DispositionPolicyMetadata metadata) {
    /** Compatibility constructor for policies which did not originate from a signed document. */
    public DispositionPolicy(String version, List<DispositionRule> rules) { this(version, rules, null); }
    public DispositionPolicy { Objects.requireNonNull(version, "version"); Objects.requireNonNull(rules, "rules"); if (version.isBlank()) throw new IllegalArgumentException("version must not be blank"); rules = List.copyOf(rules); Set<String> ids = new java.util.HashSet<>(); for (DispositionRule rule : rules) if (!ids.add(rule.ruleId())) throw new IllegalArgumentException("duplicate rule id: " + rule.ruleId()); }
}
