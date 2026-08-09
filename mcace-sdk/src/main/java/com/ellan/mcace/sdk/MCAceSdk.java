package com.ellan.mcace.sdk;

/**
 * SDK-wide compatibility constants.
 *
 * <p>The API version is intentionally independent from the MCAce server build version. A compatible
 * minor revision can add optional capabilities; a major revision may change a public contract.</p>
 *
 * @since 1.0
 */
public final class MCAceSdk {
    /** Current stable public API version. */
    public static final MCAceSdkVersion API_VERSION = new MCAceSdkVersion(1, 0);

    private static final MCAceSdkDescriptor BASELINE_DESCRIPTOR = new MCAceSdkDescriptor(
            API_VERSION,
            MCAceCapability.baseline());

    private MCAceSdk() {
    }

    /**
     * Returns the capabilities guaranteed by an implementation that only supplies player snapshots.
     *
     * @return immutable baseline descriptor
     */
    public static MCAceSdkDescriptor baselineDescriptor() {
        return BASELINE_DESCRIPTOR;
    }
}
