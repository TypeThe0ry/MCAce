package com.ellan.mcace.velocity;

import com.velocitypowered.api.proxy.messages.MinecraftChannelIdentifier;
import com.velocitypowered.api.proxy.messages.ChannelIdentifier;
import com.velocitypowered.api.proxy.Player;
import com.ellan.mcace.core.proxy.ProxyAdapterTransportContract;

public final class MCAceVelocityChannels {
    public static final MinecraftChannelIdentifier HANDSHAKE = MinecraftChannelIdentifier.create("mcace", "handshake");
    public static final MinecraftChannelIdentifier PAYLOAD = MinecraftChannelIdentifier.create("mcace", "payload");
    public static final MinecraftChannelIdentifier ADMISSION = MinecraftChannelIdentifier.create("mcace", "admission");
    public static final MinecraftChannelIdentifier BACKEND_CONTEXT = MinecraftChannelIdentifier.create("mcace", "context");

    private MCAceVelocityChannels() {
    }

    static ProxyAdapterTransportContract.InboundDecision inboundDecision(
            ChannelIdentifier identifier, boolean playerSource) {
        return ProxyAdapterTransportContract.decide(identifier.getId(), playerSource);
    }

    static boolean isPlayerSource(Object source) {
        return source instanceof Player;
    }
}
