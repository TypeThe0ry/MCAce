package com.ellan.mcace.sdk;

/**
 * Content-free explanatory risk reason from the JDK-only interop contract.
 *
 * @param code stable reason code
 * @param weight non-negative contribution
 * @param source source label
 * @param observedAtEpochMs server-observed timestamp
 * @param corroborated whether another trusted source corroborated it
 * @since 1.0
 */
public record MCAceInteropRiskReason(
        String code, int weight, String source, long observedAtEpochMs, boolean corroborated) {
    /** Creates validated reason data. */
    public MCAceInteropRiskReason {
        code = MCAceInteropPayload.requireToken(code, "code");
        source = MCAceInteropPayload.requireText(source, "source");
        if (weight < 0 || observedAtEpochMs < 0) {
            throw new IllegalArgumentException("weight and observedAtEpochMs must not be negative");
        }
    }
}
