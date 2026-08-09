package com.ellan.mcace.cloud.auth;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public record AuthenticatedServer(UUID tokenId, String serverId, Set<ApiScope> scopes, Instant expiresAt) {
    public AuthenticatedServer {
        Objects.requireNonNull(tokenId, "tokenId");
        serverId = ServerIdentity.validateServerId(serverId);
        scopes = Set.copyOf(Objects.requireNonNull(scopes, "scopes"));
        Objects.requireNonNull(expiresAt, "expiresAt");
    }

    public boolean permits(ApiScope scope) {
        return scopes.contains(scope);
    }
}
