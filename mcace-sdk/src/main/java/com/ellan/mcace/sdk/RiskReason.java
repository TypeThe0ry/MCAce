package com.ellan.mcace.sdk;

import java.time.Instant;
import java.util.Objects;

/**
 * Immutable explanation for a component of a player's published risk score.
 *
 * <p>A reason is review context, not evidence of misconduct or permission for automatic punishment.</p>
 *
 * @param code stable reason code
 * @param weight non-negative contribution to the published score
 * @param source observation source label
 * @param observedAt server-recorded observation time
 * @param corroborated whether another trusted source corroborated the observation
 * @since 1.0
 */
public record RiskReason(String code, int weight, String source, Instant observedAt, boolean corroborated) {
    /** Creates a validated immutable risk reason. */
    public RiskReason {
        Objects.requireNonNull(code, "code");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(observedAt, "observedAt");
        code = SdkValidation.boundedText(code, "code");
        source = SdkValidation.boundedText(source, "source");
        if (weight < 0) {
            throw new IllegalArgumentException("weight must not be negative");
        }
    }
}
