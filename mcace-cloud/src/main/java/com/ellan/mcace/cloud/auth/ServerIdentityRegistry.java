package com.ellan.mcace.cloud.auth;

import java.util.Optional;

public interface ServerIdentityRegistry {
    Optional<ServerIdentity> find(String serverId);
}
