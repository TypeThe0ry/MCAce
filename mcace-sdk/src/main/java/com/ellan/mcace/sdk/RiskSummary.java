package com.ellan.mcace.sdk;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Read-only, explainable risk state derived from a published security snapshot.
 *
 * <p>This type intentionally contains no disposition or punishment instruction. A consumer must treat
 * it as review context and combine it with server-authoritative observations.</p>
 *
 * @param playerId player UUID
 * @param score non-negative published risk score
 * @param band published risk band
 * @param policyVersion policy that produced the score
 * @param evaluatedAt evaluation time
 * @param reasons immutable explanatory reasons
 * @since 1.0
 */
public record RiskSummary(
        UUID playerId,
        int score,
        RiskBand band,
        String policyVersion,
        Instant evaluatedAt,
        List<RiskReason> reasons) {
    /** Creates a validated immutable risk summary. */
    public RiskSummary {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(band, "band");
        policyVersion = SdkValidation.boundedText(policyVersion, "policyVersion");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        reasons = List.copyOf(Objects.requireNonNull(reasons, "reasons"));
        SdkValidation.boundedSize(reasons, "reasons");
        if (score < 0) {
            throw new IllegalArgumentException("score must not be negative");
        }
    }

    /**
     * Converts an immutable player snapshot to its risk view.
     *
     * @param snapshot source snapshot
     * @return immutable risk summary
     */
    public static RiskSummary fromSnapshot(PlayerSecuritySnapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        return new RiskSummary(
                snapshot.playerId(),
                snapshot.riskScore(),
                snapshot.riskBand(),
                snapshot.policyVersion(),
                snapshot.evaluatedAt(),
                snapshot.reasons());
    }
}
