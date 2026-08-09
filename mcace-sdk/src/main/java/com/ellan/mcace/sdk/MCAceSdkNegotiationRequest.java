package com.ellan.mcace.sdk;

import java.util.Objects;
import java.util.Set;

/**
 * Consumer requirements used to negotiate an {@link MCAceApi} without changing server state.
 *
 * @param minimumVersion lowest compatible stable SDK version
 * @param requiredCapabilities optional features the consumer will use
 * @since 1.0
 */
public record MCAceSdkNegotiationRequest(
        MCAceSdkVersion minimumVersion, Set<MCAceCapability> requiredCapabilities) {
    /** Creates an immutable negotiation request. */
    public MCAceSdkNegotiationRequest {
        Objects.requireNonNull(minimumVersion, "minimumVersion");
        requiredCapabilities = Set.copyOf(Objects.requireNonNull(requiredCapabilities, "requiredCapabilities"));
    }

    /**
     * Evaluates this request against an offered descriptor.
     *
     * @param offered implementation descriptor
     * @return immutable compatibility result
     */
    public MCAceSdkNegotiationResult evaluate(MCAceSdkDescriptor offered) {
        Objects.requireNonNull(offered, "offered");
        Set<MCAceCapability> missing = requiredCapabilities.stream()
                .filter(capability -> !offered.capabilities().contains(capability))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        return new MCAceSdkNegotiationResult(
                offered,
                offered.apiVersion().supports(minimumVersion) && missing.isEmpty(),
                missing);
    }
}
