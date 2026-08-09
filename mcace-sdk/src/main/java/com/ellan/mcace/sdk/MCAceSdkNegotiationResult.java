package com.ellan.mcace.sdk;

import java.util.Objects;
import java.util.Set;

/**
 * Immutable result of a read-only SDK compatibility negotiation.
 *
 * @param offered descriptor returned by the API implementation
 * @param compatible whether the requested version and capabilities are satisfied
 * @param missingCapabilities requested capabilities that were not offered
 * @since 1.0
 */
public record MCAceSdkNegotiationResult(
        MCAceSdkDescriptor offered, boolean compatible, Set<MCAceCapability> missingCapabilities) {
    /** Creates an immutable result with internally consistent compatibility state. */
    public MCAceSdkNegotiationResult {
        Objects.requireNonNull(offered, "offered");
        missingCapabilities = Set.copyOf(Objects.requireNonNull(missingCapabilities, "missingCapabilities"));
        if (compatible && !missingCapabilities.isEmpty()) {
            throw new IllegalArgumentException("a compatible result cannot have missing capabilities");
        }
    }
}
