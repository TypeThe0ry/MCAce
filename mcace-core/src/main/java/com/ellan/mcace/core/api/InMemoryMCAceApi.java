package com.ellan.mcace.core.api;

import com.ellan.mcace.sdk.MCAceApi;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public final class InMemoryMCAceApi implements MCAceApi {
    private final ConcurrentMap<UUID, PlayerSecuritySnapshot> snapshots = new ConcurrentHashMap<>();

    @Override
    public Optional<PlayerSecuritySnapshot> snapshot(UUID playerId) {
        return Optional.ofNullable(snapshots.get(Objects.requireNonNull(playerId, "playerId")));
    }

    public void publish(PlayerSecuritySnapshot snapshot) {
        Objects.requireNonNull(snapshot, "snapshot");
        snapshots.put(snapshot.playerId(), snapshot);
    }

    public void remove(UUID playerId) {
        snapshots.remove(Objects.requireNonNull(playerId, "playerId"));
    }
}
