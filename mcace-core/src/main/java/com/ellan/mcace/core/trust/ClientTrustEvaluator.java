package com.ellan.mcace.core.trust;

import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.RiskBand;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Deterministic connection trust state machine used by server adapters and evidence reports.
 *
 * <p>Client observations can move a connection to {@link ClientTrustState#SUSPECT} when a
 * separately reviewed catalogue match is present, but only an independent server signal is
 * represented by {@code serverConfirmedFinding}.  This keeps the client self-report advisory
 * while still giving the proxy one stable state to render and route.</p>
 */
public final class ClientTrustEvaluator {
    public ClientTrustAssessment evaluate(
            AdmissionStatus admissionStatus,
            TrustLevel trustLevel,
            RiskBand riskBand,
            Instant lastObservationAt,
            Instant evaluatedAt,
            Duration staleAfter,
            boolean serverConfirmedFinding,
            boolean reviewedHighRiskArtifact) {
        Objects.requireNonNull(admissionStatus, "admissionStatus");
        Objects.requireNonNull(trustLevel, "trustLevel");
        Objects.requireNonNull(riskBand, "riskBand");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        Objects.requireNonNull(staleAfter, "staleAfter");
        if (staleAfter.isZero() || staleAfter.isNegative()) {
            throw new IllegalArgumentException("staleAfter must be positive");
        }
        if (trustLevel == TrustLevel.UNRECOGNIZED) {
            throw new IllegalArgumentException("unrecognized wire trust level");
        }

        List<String> reasons = new ArrayList<>();
        if (admissionStatus == AdmissionStatus.BLOCKED) {
            reasons.add("admission-blocked");
            return new ClientTrustAssessment(ClientTrustState.BLOCKED, reasons, evaluatedAt);
        }
        if (serverConfirmedFinding) {
            reasons.add("server-confirmed-finding");
            return new ClientTrustAssessment(ClientTrustState.SUSPECT, reasons, evaluatedAt);
        }
        if (reviewedHighRiskArtifact || riskBand == RiskBand.INVESTIGATION) {
            if (reviewedHighRiskArtifact) reasons.add("reviewed-high-risk-artifact");
            if (riskBand == RiskBand.INVESTIGATION) reasons.add("risk-band-investigation");
            return new ClientTrustAssessment(ClientTrustState.SUSPECT, reasons, evaluatedAt);
        }
        if (admissionStatus != AdmissionStatus.VERIFIED || trustLevel != TrustLevel.VERIFIED) {
            if (admissionStatus != AdmissionStatus.VERIFIED) {
                reasons.add("admission-" + admissionStatus.name().toLowerCase(java.util.Locale.ROOT));
            }
            if (trustLevel != TrustLevel.VERIFIED) reasons.add("wire-trust-not-verified");
            return new ClientTrustAssessment(ClientTrustState.UNTRUSTED, reasons, evaluatedAt);
        }
        if (lastObservationAt == null) {
            reasons.add("observation-never-seen");
            return new ClientTrustAssessment(ClientTrustState.STALE, reasons, evaluatedAt);
        }
        if (lastObservationAt.isAfter(evaluatedAt)
                || evaluatedAt.isAfter(lastObservationAt.plus(staleAfter))) {
            reasons.add(lastObservationAt.isAfter(evaluatedAt)
                    ? "observation-from-the-future" : "observation-expired");
            return new ClientTrustAssessment(ClientTrustState.STALE, reasons, evaluatedAt);
        }
        reasons.add("verified-and-fresh");
        return new ClientTrustAssessment(ClientTrustState.TRUSTED, reasons, evaluatedAt);
    }
}
