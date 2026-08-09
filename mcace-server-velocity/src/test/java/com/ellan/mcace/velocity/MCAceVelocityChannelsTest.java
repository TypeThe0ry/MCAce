package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.proxy.ProxyAdapterTransportContract;
import com.velocitypowered.api.proxy.Player;
import java.lang.reflect.Proxy;
import org.junit.jupiter.api.Test;

final class MCAceVelocityChannelsTest {
    @Test
    void delegatesOwnedChannelsToTheSharedTransportContract() {
        assertEquals(ProxyAdapterTransportContract.InboundDecision.CLIENT_AUTH,
                MCAceVelocityChannels.inboundDecision(MCAceVelocityChannels.HANDSHAKE, true));
        assertEquals(ProxyAdapterTransportContract.InboundDecision.CLIENT_AUTH,
                MCAceVelocityChannels.inboundDecision(MCAceVelocityChannels.PAYLOAD, true));
        assertEquals(ProxyAdapterTransportContract.InboundDecision.CONSUME_ONLY,
                MCAceVelocityChannels.inboundDecision(MCAceVelocityChannels.ADMISSION, true));
        assertEquals(ProxyAdapterTransportContract.InboundDecision.CONSUME_ONLY,
                MCAceVelocityChannels.inboundDecision(MCAceVelocityChannels.HANDSHAKE, false));
    }

    @Test
    void serverOrBackendSourceCannotEnterTheClientHandshakeCoordinator() {
        assertFalse(MCAceVelocityChannels.isPlayerSource(new Object()));
        Player player = (Player) Proxy.newProxyInstance(
                Player.class.getClassLoader(), new Class<?>[] {Player.class}, (proxy, method, args) -> null);
        assertTrue(MCAceVelocityChannels.isPlayerSource(player));
    }
}
