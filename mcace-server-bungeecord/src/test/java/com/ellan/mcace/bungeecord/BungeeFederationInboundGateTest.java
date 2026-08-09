package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.ellan.mcace.protocol.generated.EnvelopeHeader;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import org.junit.jupiter.api.Test;

final class BungeeFederationInboundGateTest {
    @Test
    void routesOnlyClientDirectionsAndDropsServerDirections() {
        assertEquals(BungeeFederationInboundGate.Decision.CONSENT_RESPONSE,
                BungeeFederationInboundGate.classify(true, frame(PacketType.FEDERATION_CONSENT_RESPONSE)));
        assertEquals(BungeeFederationInboundGate.Decision.PRESENTATION,
                BungeeFederationInboundGate.classify(true, frame(PacketType.FEDERATION_PRESENTATION)));
        assertEquals(BungeeFederationInboundGate.Decision.DROP_SERVER_ONLY,
                BungeeFederationInboundGate.classify(true, frame(PacketType.FEDERATION_CONSENT_REQUEST)));
        assertEquals(BungeeFederationInboundGate.Decision.DROP_SERVER_ONLY,
                BungeeFederationInboundGate.classify(true, frame(PacketType.FEDERATION_GRANT)));
        assertEquals(BungeeFederationInboundGate.Decision.NOT_FEDERATION,
                BungeeFederationInboundGate.classify(true, frame(PacketType.HEARTBEAT)));
        assertEquals(BungeeFederationInboundGate.Decision.DROP_SERVER_ONLY,
                BungeeFederationInboundGate.classify(false, frame(PacketType.FEDERATION_PRESENTATION)));
    }

    private static byte[] frame(PacketType type) {
        return SignedEnvelope.newBuilder().setHeader(
                EnvelopeHeader.newBuilder().setPacketType(type)).build().toByteArray();
    }
}
