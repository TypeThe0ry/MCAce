package com.ellan.mcace.core.disposition;

import java.util.Objects;
import java.util.UUID;

/** Empty fields are wildcards. A player id is an exact, auditable exception scope. */
public record RuleScope(String proxy, String backend, String world, String gameMode, String permissionGroup, UUID playerId) {
    public RuleScope { validate(proxy); validate(backend); validate(world); validate(gameMode); validate(permissionGroup); }
    /** Compatibility constructor for policies predating proxy-scoped rules. */
    public RuleScope(String backend, String world, String gameMode, String permissionGroup, UUID playerId) {
        this(null, backend, world, gameMode, permissionGroup, playerId);
    }
    private static void validate(String v) { if (v != null && v.isBlank()) throw new IllegalArgumentException("scope values must not be blank"); }
    public boolean matches(EvaluationContext c) { Objects.requireNonNull(c, "context"); return (proxy == null || proxy.equals(c.proxy())) && (backend == null || backend.equals(c.backend())) && (world == null || world.equals(c.world())) && (gameMode == null || gameMode.equals(c.gameMode())) && (permissionGroup == null || c.permissionGroups().contains(permissionGroup)) && (playerId == null || playerId.equals(c.playerId())); }
    public int specificity() { return (proxy == null ? 0 : 1) + (backend == null ? 0 : 1) + (world == null ? 0 : 1) + (gameMode == null ? 0 : 1) + (permissionGroup == null ? 0 : 1) + (playerId == null ? 0 : 1); }
    public boolean exactException() { return playerId != null; }
    public static RuleScope global() { return new RuleScope(null, null, null, null, null, null); }
}
