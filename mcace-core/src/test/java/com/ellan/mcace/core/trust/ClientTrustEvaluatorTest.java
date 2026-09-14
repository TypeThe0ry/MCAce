package com.ellan.mcace.core.trust;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.RiskBand;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

final class ClientTrustEvaluatorTest {
    private static final Instant NOW = Instant.parse("2026-08-22T00:00:00Z");
    private static final Duration TTL = Duration.ofMinutes(5);

    @Test
    void reportsTrustedOnlyForVerifiedFreshSessions() {
        ClientTrustAssessment assessment = evaluate(NOW.minusSeconds(30), false, false,
                AdmissionStatus.VERIFIED, TrustLevel.VERIFIED, RiskBand.NORMAL);
        assertEquals(ClientTrustState.TRUSTED, assessment.state());
        assertEquals("verified-and-fresh", assessment.reasons().getFirst());
    }

    @Test
    void missingClientIsUntrustedAndNeverSilentlyTrusted() {
        ClientTrustAssessment assessment = evaluate(null, false, false,
                AdmissionStatus.LIMITED, TrustLevel.UNKNOWN, RiskBand.NORMAL);
        assertEquals(ClientTrustState.UNTRUSTED, assessment.state());
    }

    @Test
    void staleObservationIsDistinctFromUntrustedAdmission() {
        ClientTrustAssessment assessment = evaluate(NOW.minus(Duration.ofMinutes(6)), false, false,
                AdmissionStatus.VERIFIED, TrustLevel.VERIFIED, RiskBand.NORMAL);
        assertEquals(ClientTrustState.STALE, assessment.state());
    }

    @Test
    void independentFindingTakesSuspectPrecedence() {
        ClientTrustAssessment assessment = evaluate(NOW.minusSeconds(1), true, false,
                AdmissionStatus.VERIFIED, TrustLevel.VERIFIED, RiskBand.NORMAL);
        assertEquals(ClientTrustState.SUSPECT, assessment.state());
    }

    @Test
    void blockedAdmissionTakesHighestPrecedence() {
        ClientTrustAssessment assessment = evaluate(NOW.minusSeconds(1), true, true,
                AdmissionStatus.BLOCKED, TrustLevel.VERIFIED, RiskBand.INVESTIGATION);
        assertEquals(ClientTrustState.BLOCKED, assessment.state());
    }

    @Test
    void rejectsInvalidFreshnessWindow() {
        assertThrows(IllegalArgumentException.class, () -> new ClientTrustEvaluator().evaluate(
                AdmissionStatus.VERIFIED, TrustLevel.VERIFIED, RiskBand.NORMAL, NOW, NOW,
                Duration.ZERO, false, false));
    }

    private static ClientTrustAssessment evaluate(
            Instant lastObservation, boolean serverConfirmed, boolean reviewed,
            AdmissionStatus admission, TrustLevel trust, RiskBand risk) {
        return new ClientTrustEvaluator().evaluate(
                admission, trust, risk, lastObservation, NOW, TTL, serverConfirmed, reviewed);
    }
}
