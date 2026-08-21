package com.ellan.mcace.core.context;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Context observed by the Paper/Folia backend for one player.
 *
 * <p>Backend identity is intentionally not part of this record. A proxy must derive that identity
 * from the server connection which delivered the plugin message.</p>
 */
public record BackendContextReport(
        UUID playerId,
        long admissionTransportSequence,
        long reportSequence,
        String worldId,
        String gameMode,
        Instant observedAt) {
    public BackendContextReport {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(worldId, "worldId");
        Objects.requireNonNull(gameMode, "gameMode");
        Objects.requireNonNull(observedAt, "observedAt");
        if (admissionTransportSequence <= 0L || reportSequence <= 0L) {
            throw new IllegalArgumentException("backend context sequences must be positive");
        }
    }
}
