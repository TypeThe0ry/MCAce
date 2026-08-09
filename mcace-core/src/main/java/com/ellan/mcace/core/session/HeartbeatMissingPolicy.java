package com.ellan.mcace.core.session;

import java.util.Objects;

/** Optional, session-only reaction to sustained missing heartbeats. Disabled by default. */
public record HeartbeatMissingPolicy(boolean enabled, int consecutiveMissingPolls, Action action) {
    public enum Action { NOTICE, LIMITED_ROUTE }
    public HeartbeatMissingPolicy {
        Objects.requireNonNull(action, "action");
        if (enabled && (consecutiveMissingPolls < 2 || consecutiveMissingPolls > 300)) {
            throw new IllegalArgumentException("missing heartbeat threshold must be between 2 and 300 polls");
        }
        if (!enabled && consecutiveMissingPolls < 0) throw new IllegalArgumentException("missing threshold must not be negative");
    }
    public static HeartbeatMissingPolicy disabled() { return new HeartbeatMissingPolicy(false, 0, Action.NOTICE); }
}
