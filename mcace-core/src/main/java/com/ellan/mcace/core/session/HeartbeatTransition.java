package com.ellan.mcace.core.session;

import com.ellan.mcace.protocol.heartbeat.HeartbeatHealth;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** A monitor-only heartbeat health change. It is never an admission decision. */
public record HeartbeatTransition(
        UUID playerId, String sessionId, HeartbeatHealth previous, HeartbeatHealth current, Instant observedAt) {
    public HeartbeatTransition {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(previous, "previous");
        Objects.requireNonNull(current, "current");
        Objects.requireNonNull(observedAt, "observedAt");
        if (sessionId.isBlank() || previous == current) {
            throw new IllegalArgumentException("heartbeat transition must change a non-blank session");
        }
    }
}
