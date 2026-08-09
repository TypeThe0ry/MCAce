package com.ellan.mcace.sdk;

import java.util.Objects;
import java.util.UUID;

/**
 * Consumer-local non-sensitive session metadata from the JDK-only interop contract.
 *
 * @param playerId player UUID
 * @param sessionId opaque server session UUID
 * @param state symbolic session-state name
 * @param trustLevel symbolic trust-level name
 * @param startedAtEpochMs session start timestamp
 * @param lastObservedAtEpochMs latest server observation timestamp
 * @since 1.0
 */
public record MCAceInteropSessionSummary(
        UUID playerId,
        UUID sessionId,
        String state,
        String trustLevel,
        long startedAtEpochMs,
        long lastObservedAtEpochMs) {
    /** Creates validated immutable session data. */
    public MCAceInteropSessionSummary {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        state = MCAceInteropPayload.requireToken(state, "state");
        trustLevel = MCAceInteropPayload.requireToken(trustLevel, "trustLevel");
        if (startedAtEpochMs < 0 || lastObservedAtEpochMs < startedAtEpochMs) {
            throw new IllegalArgumentException("session timestamps are invalid");
        }
    }
}
