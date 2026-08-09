package com.ellan.mcace.cloud.auth;

import java.security.PublicKey;
import java.util.Objects;
import java.util.Set;

public record ServerIdentity(String serverId, PublicKey publicKey, Set<ApiScope> scopes) {
    public ServerIdentity {
        serverId = validateServerId(serverId);
        Objects.requireNonNull(publicKey, "publicKey");
        scopes = Set.copyOf(Objects.requireNonNull(scopes, "scopes"));
        if (scopes.isEmpty()) throw new IllegalArgumentException("server identity requires at least one scope");
    }

    public static String validateServerId(String serverId) {
        Objects.requireNonNull(serverId, "serverId");
        if (!serverId.matches("[A-Za-z0-9._-]{1,64}")) {
            throw new IllegalArgumentException("invalid server identity");
        }
        return serverId;
    }
}
