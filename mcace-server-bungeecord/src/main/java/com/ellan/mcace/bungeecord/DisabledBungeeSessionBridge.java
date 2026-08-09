package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.sdk.MCAceApi;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Safe default while no signed-policy/session provider is installed. */
final class DisabledBungeeSessionBridge implements BungeeSessionBridge {
    private final InMemoryMCAceApi api = new InMemoryMCAceApi();

    @Override
    public Optional<byte[]> begin(UUID playerId) {
        return Optional.empty();
    }

    @Override
    public BungeeBridgeAction receive(UUID playerId, byte[] encodedFrame) {
        return BungeeBridgeAction.none();
    }

    @Override
    public List<PlayerSecuritySnapshot> expireTimedOut() {
        return List.of();
    }

    @Override
    public void remove(UUID playerId) {
        api.remove(playerId);
    }

    @Override
    public MCAceApi api() {
        return api;
    }
}
