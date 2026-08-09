package com.ellan.mcace.core.disposition;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public record EvaluationContext(UUID playerId, String proxy, String backend, String world, String gameMode, Set<String> permissionGroups, Instant evaluatedAt) {
    public EvaluationContext { Objects.requireNonNull(playerId, "playerId"); Objects.requireNonNull(permissionGroups, "permissionGroups"); Objects.requireNonNull(evaluatedAt, "evaluatedAt"); permissionGroups = Set.copyOf(permissionGroups); }
    /** Compatibility constructor for callers that do not have a proxy identity. */
    public EvaluationContext(UUID playerId, String backend, String world, String gameMode, Set<String> permissionGroups, Instant evaluatedAt) {
        this(playerId, null, backend, world, gameMode, permissionGroups, evaluatedAt);
    }
}
