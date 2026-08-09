package com.ellan.mcace.sdk;

import com.ellan.mcace.protocol.generated.TrustLevel;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Non-sensitive, read-only lifecycle metadata for a player session.
 *
 * <p>The session identifier is an opaque server-generated correlation identifier. It is not a device
 * identifier and must not be used for cross-service tracking.</p>
 *
 * @param playerId player UUID
 * @param sessionId opaque session UUID
 * @param state current session state
 * @param trustLevel current published trust level
 * @param startedAt session start time
 * @param lastObservedAt latest server observation time
 * @since 1.0
 */
public record SessionSecuritySummary(
        UUID playerId,
        UUID sessionId,
        SessionState state,
        TrustLevel trustLevel,
        Instant startedAt,
        Instant lastObservedAt) {
    /** Creates validated immutable session metadata. */
    public SessionSecuritySummary {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(trustLevel, "trustLevel");
        Objects.requireNonNull(startedAt, "startedAt");
        Objects.requireNonNull(lastObservedAt, "lastObservedAt");
        if (lastObservedAt.isBefore(startedAt)) {
            throw new IllegalArgumentException("lastObservedAt must not precede startedAt");
        }
    }
}
