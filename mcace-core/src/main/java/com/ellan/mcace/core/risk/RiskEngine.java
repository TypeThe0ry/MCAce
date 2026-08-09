package com.ellan.mcace.core.risk;

import com.ellan.mcace.sdk.RiskBand;
import com.ellan.mcace.sdk.RiskReason;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

public final class RiskEngine {
    private final RiskPolicy policy;

    public RiskEngine(RiskPolicy policy) {
        this.policy = Objects.requireNonNull(policy, "policy");
    }

    public RiskAssessment evaluate(Collection<ObservedRiskEvent> events) {
        Objects.requireNonNull(events, "events");
        List<RiskReason> reasons = events.stream()
                .map(event -> new RiskReason(
                        event.type().name(),
                        policy.weights().getOrDefault(event.type(), 0),
                        event.source(),
                        event.observedAt(),
                        event.corroborated()))
                .sorted(Comparator.comparing(RiskReason::observedAt).thenComparing(RiskReason::code))
                .toList();
        int score = reasons.stream().mapToInt(RiskReason::weight).reduce(0, Math::addExact);
        return new RiskAssessment(score, band(score), policy.version(), reasons);
    }

    private RiskBand band(int score) {
        if (score >= policy.investigationThreshold()) {
            return RiskBand.INVESTIGATION;
        }
        if (score >= policy.restrictedThreshold()) {
            return RiskBand.RESTRICTED;
        }
        if (score >= policy.watchThreshold()) {
            return RiskBand.WATCH;
        }
        return RiskBand.NORMAL;
    }
}
