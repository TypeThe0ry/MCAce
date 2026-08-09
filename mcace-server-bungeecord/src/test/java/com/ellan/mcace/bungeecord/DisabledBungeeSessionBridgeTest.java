package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class DisabledBungeeSessionBridgeTest {
    @Test
    void safeDefaultDoesNotCreateTrustStateOrPunishmentSignals() {
        DisabledBungeeSessionBridge bridge = new DisabledBungeeSessionBridge();
        UUID playerId = UUID.randomUUID();

        assertFalse(bridge.begin(playerId).isPresent());
        assertFalse(bridge.receive(playerId, new byte[] {1}).protocolViolation());
        assertTrue(bridge.expireTimedOut().isEmpty());
        assertFalse(bridge.api().snapshot(playerId).isPresent());
    }
}
