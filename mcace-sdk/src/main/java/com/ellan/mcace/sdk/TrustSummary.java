package com.ellan.mcace.sdk;

import com.ellan.mcace.protocol.generated.TrustLevel;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Read-only trust state derived from a published {@link PlayerSecuritySnapshot}.
 *
 * @param playerId player UUID
 * @param trustLevel published trust level
 * @param admissionStatus published admission state
 * @param policyVersion policy that produced the state
 * @param evaluatedAt evaluation time
 * @since 1.0
 */
public record TrustSummary(
        UUID playerId,
        TrustLevel trustLevel,
        AdmissionStatus admissionStatus,
        String policyVersion,
        Instant evaluatedAt) {
    /** Creates a validated immutable trust summary. */
    public TrustSummary {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(trustLevel, "trustLevel");
        Objects.requireNonNull(admissionStatus, "admissionStatus");
        policyVersion = SdkValidation.boundedText(policyVersion, "policyVersion");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");
    }

    /**
     * Converts an immutable player snapshot to its trust view.
     *
     * @param snapshot source snapshot
     * @return immutable trust summary
     */
    public static TrustSummary fromSnapshot(PlayerSecuritySnapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        return new TrustSummary(
                snapshot.playerId(),
                snapshot.trustLevel(),
                snapshot.admissionStatus(),
                snapshot.policyVersion(),
                snapshot.evaluatedAt());
    }

    /**
     * Reports whether this summary represents a verified admission state.
     *
     * @return true only for verified state
     */
    public boolean verified() {
        return trustLevel != TrustLevel.UNKNOWN && admissionStatus == AdmissionStatus.VERIFIED;
    }
}
