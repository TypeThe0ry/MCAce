package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.ProtocolConstants;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

final class MCAcePayloadTest {
    @Test
    void codecUsesThePluginMessageBodyWithoutAnInnerLengthPrefix() {
        byte[] frame = new byte[] {0x00, 0x11, 0x22, (byte) 0xFF};
        ByteBuf buffer = Unpooled.buffer();

        MCAcePayload.writeFrame(buffer, frame);

        assertEquals(frame.length, buffer.readableBytes());
        assertArrayEquals(frame, MCAcePayload.readFrame(buffer));
        assertEquals(0, buffer.readableBytes());
    }

    @Test
    void decoderRejectsAnOversizedPluginMessageBody() {
        ByteBuf buffer = Unpooled.wrappedBuffer(
                new byte[ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES + 1]);

        assertThrows(IllegalArgumentException.class, () -> MCAcePayload.readFrame(buffer));
    }

    @Test
    void transferPayloadUsesTheSameThirtyKibFrameBudget() {
        assertThrows(IllegalArgumentException.class, () -> new MCAceTransferPayload(
                new byte[ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES + 1]));
    }

    @Test
    void backendContextAdvertisementIsBoundedAndDefensivelyCopied() {
        byte[] frame = new byte[] {0x01};
        MCAceBackendContextPayload payload = new MCAceBackendContextPayload(frame);
        frame[0] = 0x02;
        assertArrayEquals(new byte[] {0x01}, payload.data());
        assertThrows(IllegalArgumentException.class, () -> new MCAceBackendContextPayload(
                new byte[ProtocolConstants.MAX_BACKEND_CONTEXT_FRAME_BYTES + 1]));
    }

    @Test
    void evidenceSmokeNeverExitsAtAuthenticationAndOnlyExitsAfterComplete() {
        assertTrue(MCAceFabricClient.shouldStopPlatformSmokeAfterAuthentication(true, false));
        assertEquals(false, MCAceFabricClient.shouldStopPlatformSmokeAfterAuthentication(true, true));
        assertEquals(false, MCAceFabricClient.shouldStopPlatformSmokeAfterAuthentication(false, true));
        assertEquals(false, MCAceFabricClient.shouldStopPlatformSmokeAfterEvidence(false));
        assertTrue(MCAceFabricClient.shouldStopPlatformSmokeAfterEvidence(true));
    }
}
