package com.ellan.mcace.sdk;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Content-free evidence metadata for human review.
 *
 * <p>This public boundary never exposes raw content, hashes, storage locations, file names, encryption
 * keys, or a disposition recommendation. In particular, client-reported evidence must not be the sole
 * basis for an automatic punishment.</p>
 *
 * @param evidenceId opaque server evidence identifier
 * @param playerId player UUID
 * @param type content category
 * @param state lifecycle state
 * @param clientReported whether the underlying observation originated at the client
 * @param capturedAt reported capture time, when known
 * @param expiresAt configured retention expiry, when raw retention exists
 * @since 1.0
 */
public record EvidenceSummary(
        UUID evidenceId,
        UUID playerId,
        EvidenceType type,
        EvidenceState state,
        boolean clientReported,
        Instant capturedAt,
        Instant expiresAt) {
    /** Creates validated immutable, content-free evidence metadata. */
    public EvidenceSummary {
        Objects.requireNonNull(evidenceId, "evidenceId");
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(state, "state");
        if (capturedAt != null && expiresAt != null && expiresAt.isBefore(capturedAt)) {
            throw new IllegalArgumentException("expiresAt must not precede capturedAt");
        }
    }
}
