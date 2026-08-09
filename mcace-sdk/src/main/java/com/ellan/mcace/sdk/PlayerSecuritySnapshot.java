package com.ellan.mcace.sdk;

import com.ellan.mcace.protocol.generated.TrustLevel;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Immutable, read-only player security state published by MCAce.
 *
 * <p>It contains no control method and must not be treated as sole authority for an automatic
 * punishment, particularly when its reasons originate from client-reported signals.</p>
 *
 * @param playerId player UUID
 * @param trustLevel current trust level
 * @param admissionStatus current admission status
 * @param riskScore non-negative published risk score
 * @param riskBand current risk band
 * @param policyVersion policy that produced the state
 * @param evaluatedAt evaluation time
 * @param reasons immutable explanatory reasons
 * @since 1.0
 */
public record PlayerSecuritySnapshot(
        UUID playerId,
        TrustLevel trustLevel,
        AdmissionStatus admissionStatus,
        int riskScore,
        RiskBand riskBand,
        String policyVersion,
        Instant evaluatedAt,
        List<RiskReason> reasons) {
    public PlayerSecuritySnapshot {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(trustLevel, "trustLevel");
        Objects.requireNonNull(admissionStatus, "admissionStatus");
        Objects.requireNonNull(riskBand, "riskBand");
        policyVersion = SdkValidation.boundedText(policyVersion, "policyVersion");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        reasons = List.copyOf(reasons);
        SdkValidation.boundedSize(reasons, "reasons");
        if (riskScore < 0) {
            throw new IllegalArgumentException("riskScore must not be negative");
        }
    }

    /**
     * Returns whether this snapshot has an explicit verified admission state.
     *
     * @return true only for verified state
     */
    public boolean verified() {
        return trustLevel != TrustLevel.UNKNOWN && admissionStatus == AdmissionStatus.VERIFIED;
    }
}
