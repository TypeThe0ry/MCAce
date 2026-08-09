package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.ellan.mcace.protocol.generated.EnvelopeHeader;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import org.junit.jupiter.api.Test;

final class VelocityFederationInboundGateTest {
    @Test
    void routesOnlyClientDirectionsAndDropsServerDirections() {
        assertEquals(VelocityFederationInboundGate.Decision.CONSENT_RESPONSE,
                VelocityFederationInboundGate.classify(true, frame(PacketType.FEDERATION_CONSENT_RESPONSE)));
        assertEquals(VelocityFederationInboundGate.Decision.PRESENTATION,
                VelocityFederationInboundGate.classify(true, frame(PacketType.FEDERATION_PRESENTATION)));
        assertEquals(VelocityFederationInboundGate.Decision.DROP_SERVER_ONLY,
                VelocityFederationInboundGate.classify(true, frame(PacketType.FEDERATION_CONSENT_REQUEST)));
        assertEquals(VelocityFederationInboundGate.Decision.DROP_SERVER_ONLY,
                VelocityFederationInboundGate.classify(true, frame(PacketType.FEDERATION_GRANT)));
        assertEquals(VelocityFederationInboundGate.Decision.NOT_FEDERATION,
                VelocityFederationInboundGate.classify(true, frame(PacketType.HEARTBEAT)));
        assertEquals(VelocityFederationInboundGate.Decision.DROP_SERVER_ONLY,
                VelocityFederationInboundGate.classify(false, frame(PacketType.FEDERATION_PRESENTATION)));
    }

    private static byte[] frame(PacketType type) {
        return SignedEnvelope.newBuilder().setHeader(
                EnvelopeHeader.newBuilder().setPacketType(type)).build().toByteArray();
    }
}
