package com.ellan.mcace.sdk;

import java.util.Objects;
import java.util.Set;

/**
 * Immutable version and capability descriptor supplied by an {@link MCAceApi} implementation.
 *
 * @param apiVersion stable SDK API version
 * @param capabilities read-only capabilities offered by the implementation
 * @since 1.0
 */
public record MCAceSdkDescriptor(MCAceSdkVersion apiVersion, Set<MCAceCapability> capabilities) {
    /** Creates an immutable descriptor. */
    public MCAceSdkDescriptor {
        Objects.requireNonNull(apiVersion, "apiVersion");
        capabilities = Set.copyOf(Objects.requireNonNull(capabilities, "capabilities"));
        if (!capabilities.contains(MCAceCapability.PLAYER_SECURITY_SNAPSHOT)) {
            throw new IllegalArgumentException("PLAYER_SECURITY_SNAPSHOT capability is required");
        }
    }

    /**
     * Tests whether this descriptor offers every requested capability.
     *
     * @param requiredCapabilities requested capability set
     * @return true when all required capabilities are offered
     */
    public boolean supports(Set<MCAceCapability> requiredCapabilities) {
        return capabilities.containsAll(Objects.requireNonNull(requiredCapabilities, "requiredCapabilities"));
    }
}
