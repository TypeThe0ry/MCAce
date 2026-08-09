package com.ellan.mcace.core.session;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Content-free, session-bound temporary-control state. It is never a risk or admission event. */
public record HeartbeatMissingTransition(UUID playerId, String sessionId, Kind kind,
        HeartbeatMissingPolicy.Action action, int missingPolls, Instant observedAt) {
    public enum Kind { APPLY, RECOVER }
    public HeartbeatMissingTransition {
        Objects.requireNonNull(playerId, "playerId"); Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(kind, "kind"); Objects.requireNonNull(action, "action"); Objects.requireNonNull(observedAt, "observedAt");
        if (sessionId.isBlank() || missingPolls < 0) throw new IllegalArgumentException("invalid heartbeat missing transition");
    }
}
