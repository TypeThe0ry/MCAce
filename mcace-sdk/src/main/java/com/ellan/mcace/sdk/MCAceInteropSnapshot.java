package com.ellan.mcace.sdk;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Consumer-local representation of a JDK-only interop snapshot.
 *
 * @param playerId player UUID
 * @param trustLevel symbolic trust level name
 * @param admissionStatus symbolic admission status name
 * @param riskScore non-negative risk score
 * @param riskBand symbolic risk-band name
 * @param policyVersion policy version
 * @param evaluatedAtEpochMs evaluation timestamp
 * @param reasons immutable explanatory reasons
 * @since 1.0
 */
public record MCAceInteropSnapshot(
        UUID playerId,
        String trustLevel,
        String admissionStatus,
        int riskScore,
        String riskBand,
        String policyVersion,
        long evaluatedAtEpochMs,
        List<MCAceInteropRiskReason> reasons) {
    /** Creates validated immutable snapshot data. */
    public MCAceInteropSnapshot {
        Objects.requireNonNull(playerId, "playerId");
        trustLevel = MCAceInteropPayload.requireToken(trustLevel, "trustLevel");
        admissionStatus = MCAceInteropPayload.requireToken(admissionStatus, "admissionStatus");
        riskBand = MCAceInteropPayload.requireToken(riskBand, "riskBand");
        policyVersion = MCAceInteropPayload.requireText(policyVersion, "policyVersion");
        reasons = List.copyOf(Objects.requireNonNull(reasons, "reasons"));
        if (riskScore < 0 || evaluatedAtEpochMs < 0) {
            throw new IllegalArgumentException("riskScore and evaluatedAtEpochMs must not be negative");
        }
    }
}
