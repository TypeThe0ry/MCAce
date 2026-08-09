package com.ellan.mcace.core.risk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.ellan.mcace.sdk.RiskBand;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

final class RiskEngineTest {
    private final RiskEngine engine = new RiskEngine(RiskPolicy.defaults());

    @Test
    void combinesExplainableSignals() {
        Instant time = Instant.parse("2026-08-08T08:00:00Z");
        RiskAssessment assessment = engine.evaluate(List.of(
                new ObservedRiskEvent(RiskEventType.UNKNOWN_MOD, "client-manifest", time, false),
                new ObservedRiskEvent(RiskEventType.BEHAVIOR_HIGH_RISK, "vulcan", time, true)));

        assertEquals(75, assessment.score());
        assertEquals(RiskBand.RESTRICTED, assessment.band());
        assertEquals(2, assessment.reasons().size());
    }

    @Test
    void boundaryValuesMatchPolicy() {
        Instant time = Instant.EPOCH;
        assertEquals(
                RiskBand.WATCH,
                engine.evaluate(List.of(new ObservedRiskEvent(
                        RiskEventType.MISSING_MCACE, "velocity", time, false))).band());
        assertEquals(
                RiskBand.INVESTIGATION,
                engine.evaluate(List.of(new ObservedRiskEvent(
                        RiskEventType.AUTH_REPLAY, "protocol", time, true))).band());
    }
}
