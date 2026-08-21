package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.proxy.ProxyAdapterTransportContract;

/** Pure source/channel boundary used before any Bungee session bridge invocation. */
final class BungeeInboundFrameGate {
    enum Decision {
        IGNORE,
        CONSUME_ONLY,
        BACKEND_CONTEXT,
        CLIENT_AUTH
    }

    private BungeeInboundFrameGate() {
    }

    static Decision decide(String channel, boolean playerSource) {
        return switch (ProxyAdapterTransportContract.decide(channel, playerSource)) {
            case IGNORE -> Decision.IGNORE;
            case CONSUME_ONLY -> Decision.CONSUME_ONLY;
            case BACKEND_CONTEXT -> Decision.BACKEND_CONTEXT;
            case CLIENT_AUTH -> Decision.CLIENT_AUTH;
        };
    }
}
