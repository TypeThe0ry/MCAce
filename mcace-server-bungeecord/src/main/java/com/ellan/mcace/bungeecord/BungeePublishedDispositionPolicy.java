package com.ellan.mcace.bungeecord;

import java.util.Objects;

/** Non-sensitive publication summary intended for an administrative command response. */
public record BungeePublishedDispositionPolicy(String version, long sequence, long ruleCount) {
    public BungeePublishedDispositionPolicy {
        Objects.requireNonNull(version, "version");
        if (version.isBlank() || sequence <= 0 || ruleCount < 0) {
            throw new IllegalArgumentException("invalid disposition publication summary");
        }
    }
}
