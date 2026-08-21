package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.client.session.ClientHandshakeEngine.OutboundChannel;
import com.ellan.mcace.client.session.ClientHandshakeEngine.OutboundFrame;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

final class OrderedMCAceFrameSenderTest {
    @Test
    void sendsFramesInGivenOrderAcrossTheTwoFixedChannels() {
        List<OutboundFrame> frames = List.of(
                new OutboundFrame(OutboundChannel.HANDSHAKE, new byte[] {1}),
                new OutboundFrame(OutboundChannel.PAYLOAD, new byte[] {2}),
                new OutboundFrame(OutboundChannel.PAYLOAD, new byte[] {3}));
        List<OutboundChannel> sent = new ArrayList<>();

        assertTrue(OrderedMCAceFrameSender.send(frames, () -> true, new RecordingSink(sent, -1)));

        assertEquals(List.of(OutboundChannel.HANDSHAKE, OutboundChannel.PAYLOAD, OutboundChannel.PAYLOAD), sent);
    }

    @Test
    void stopsWithoutSendingRemainingFramesOnFailureOrCancellation() {
        List<OutboundFrame> frames = List.of(
                new OutboundFrame(OutboundChannel.HANDSHAKE, new byte[] {1}),
                new OutboundFrame(OutboundChannel.PAYLOAD, new byte[] {2}),
                new OutboundFrame(OutboundChannel.PAYLOAD, new byte[] {3}));
        List<OutboundChannel> sent = new ArrayList<>();

        assertFalse(OrderedMCAceFrameSender.send(frames, () -> true, new RecordingSink(sent, 1)));
        assertEquals(List.of(OutboundChannel.HANDSHAKE), sent);
        AtomicBoolean active = new AtomicBoolean(false);
        assertFalse(OrderedMCAceFrameSender.send(frames, active::get, new RecordingSink(new ArrayList<>(), -1)));
        assertEquals(List.of(0, 0, 0), frames.stream().map(frame -> (int) frame.data()[0]).toList());
    }

    @Test
    void clearsFrameBuffersAfterSuccessfulSend() {
        List<OutboundFrame> frames = List.of(
                new OutboundFrame(OutboundChannel.PAYLOAD, new byte[] {9, 8}),
                new OutboundFrame(OutboundChannel.PAYLOAD, new byte[] {7, 6}));

        assertTrue(OrderedMCAceFrameSender.send(frames, () -> true, new RecordingSink(new ArrayList<>(), -1)));

        assertEquals(List.of(0, 0), frames.stream().map(frame -> (int) frame.data()[0]).toList());
    }

    private record RecordingSink(List<OutboundChannel> sent, int failAt) implements OrderedMCAceFrameSender.FrameSink {
        @Override public boolean canSend(OutboundFrame frame) { return true; }
        @Override public void send(OutboundFrame frame) {
            if (sent.size() == failAt) throw new IllegalStateException("controlled send failure");
            sent.add(frame.channel());
        }
    }
}
