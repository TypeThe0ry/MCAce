package com.ellan.mcace.sdk;

/**
 * Major/minor version for the stable public SDK contract.
 *
 * @param major incompatible contract generation
 * @param minor backward-compatible capability generation
 * @since 1.0
 */
public record MCAceSdkVersion(int major, int minor) implements Comparable<MCAceSdkVersion> {
    /**
     * Creates a non-negative API version.
     *
     * @throws IllegalArgumentException when either component is negative
     */
    public MCAceSdkVersion {
        if (major < 0 || minor < 0) {
            throw new IllegalArgumentException("version components must not be negative");
        }
    }

    /**
     * Tests whether this offered version can satisfy a consumer's minimum version.
     *
     * @param minimumVersion requested version
     * @return true when major versions match and this minor version is at least the requested minor
     */
    public boolean supports(MCAceSdkVersion minimumVersion) {
        if (minimumVersion == null) {
            throw new NullPointerException("minimumVersion");
        }
        return major == minimumVersion.major && minor >= minimumVersion.minor;
    }

    @Override
    public int compareTo(MCAceSdkVersion other) {
        if (other == null) {
            throw new NullPointerException("other");
        }
        int majorComparison = Integer.compare(major, other.major);
        return majorComparison != 0 ? majorComparison : Integer.compare(minor, other.minor);
    }

    @Override
    public String toString() {
        return major + "." + minor;
    }
}
