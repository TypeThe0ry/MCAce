package com.ellan.mcace.core.disposition;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Deterministic policy evaluator. It never exposes a permanent-ban action. */
public final class DispositionEngine {
    private static final Comparator<DispositionRule> ORDER = Comparator
            .comparingInt((DispositionRule r) -> r.scope().specificity()).reversed()
            .thenComparing(Comparator.comparingInt(DispositionRule::priority).reversed())
            .thenComparing(Comparator.comparing(DispositionRule::scope, Comparator.comparing(RuleScope::exactException)).reversed())
            .thenComparing(Comparator.comparingInt((DispositionRule r) -> r.action().severity()).reversed())
            .thenComparing(DispositionRule::ruleId);
    public DispositionDecision evaluate(DispositionPolicy policy, EvaluationContext context, ArtifactObservation observation) {
        Objects.requireNonNull(policy, "policy"); Objects.requireNonNull(context, "context"); Objects.requireNonNull(observation, "observation");
        List<DispositionRule> candidates = new ArrayList<>(); List<RuleMatchExplanation> details = new ArrayList<>();
        for (DispositionRule rule : policy.rules()) { boolean active = rule.activeAt(context.evaluatedAt()); boolean scope = active && rule.scope().matches(context); boolean selector = scope && rule.selector().matches(observation); boolean confidence = selector && observation.confidence().ordinal() >= rule.minimumConfidence().ordinal(); boolean eligible = confidence;
            if (eligible) candidates.add(rule); details.add(new RuleMatchExplanation(rule.ruleId(), active, scope, selector, confidence, false, eligible ? "candidate" : inactiveReason(active, scope, selector, confidence))); }
        // Foundation observations are evaluated only by foundation rules. Conversely, an ordinary
        // artifact can never inherit a foundation rule merely because its selector was too broad.
        List<DispositionRule> considered = candidates.stream()
                .filter(rule -> rule.foundationSecurity() == observation.foundationSecurity())
                .toList();
        DispositionRule winner = considered.stream()
                .filter(rule -> !(rule.action() == DispositionAction.ALLOW && observation.foundationSecurity()))
                .sorted(ORDER)
                .findFirst()
                .orElse(null);
        List<RuleMatchExplanation> complete = details.stream().map(d -> new RuleMatchExplanation(d.ruleId(), d.active(), d.scopeMatched(), d.selectorMatched(), d.confidenceMatched(), winner != null && d.ruleId().equals(winner.ruleId()), winner != null && d.ruleId().equals(winner.ruleId()) ? "selected" : d.outcome())).toList();
        return new DispositionDecision(observation, winner == null ? DispositionAction.OBSERVE : winner.action(), winner == null ? Optional.empty() : Optional.of(winner.ruleId()), complete);
    }
    private static String inactiveReason(boolean active, boolean scope, boolean selector, boolean confidence) { if (!active) return "inactive"; if (!scope) return "scope-mismatch"; if (!selector) return "selector-mismatch"; if (!confidence) return "confidence-too-low"; return "not-selected"; }
}
