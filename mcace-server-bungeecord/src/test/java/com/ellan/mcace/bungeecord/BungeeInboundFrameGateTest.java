package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

final class BungeeInboundFrameGateTest {
    @Test
    void onlyPlayerHandshakeAndPayloadFramesReachTheSessionBridge() {
        // HEARTBEAT intentionally shares HANDSHAKE, so it inherits this same client-only gate.
        assertEquals(BungeeInboundFrameGate.Decision.CLIENT_AUTH,
                BungeeInboundFrameGate.decide(BungeeMCAceChannels.HANDSHAKE, true));
        assertEquals(BungeeInboundFrameGate.Decision.CLIENT_AUTH,
                BungeeInboundFrameGate.decide(BungeeMCAceChannels.PAYLOAD, true));
        assertEquals(BungeeInboundFrameGate.Decision.CONSUME_ONLY,
                BungeeInboundFrameGate.decide(BungeeMCAceChannels.ADMISSION, true));
    }

    @Test
    void backendAuthorityInjectionIsConsumedWithoutBridgeAccess() {
        assertEquals(BungeeInboundFrameGate.Decision.CONSUME_ONLY,
                BungeeInboundFrameGate.decide(BungeeMCAceChannels.HANDSHAKE, false));
        assertEquals(BungeeInboundFrameGate.Decision.CONSUME_ONLY,
                BungeeInboundFrameGate.decide(BungeeMCAceChannels.PAYLOAD, false));
        assertEquals(BungeeInboundFrameGate.Decision.CONSUME_ONLY,
                BungeeInboundFrameGate.decide(BungeeMCAceChannels.ADMISSION, false));
        assertEquals(BungeeInboundFrameGate.Decision.IGNORE,
                BungeeInboundFrameGate.decide("example:unrelated", true));
    }
}
