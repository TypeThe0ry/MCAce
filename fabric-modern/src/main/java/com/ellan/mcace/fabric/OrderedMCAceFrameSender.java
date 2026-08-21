package com.ellan.mcace.fabric;

import com.ellan.mcace.client.session.ClientHandshakeEngine.OutboundFrame;
import java.util.List;
import java.util.Objects;
import java.util.function.BooleanSupplier;

/** Executes a prebuilt frame list in order and stops permanently on cancellation or send failure. */
final class OrderedMCAceFrameSender {
    private OrderedMCAceFrameSender() {
    }

    static boolean send(List<OutboundFrame> frames, BooleanSupplier active, FrameSink sink) {
        Objects.requireNonNull(frames, "frames");
        Objects.requireNonNull(active, "active");
        Objects.requireNonNull(sink, "sink");
        for (int index = 0; index < frames.size(); index++) {
            OutboundFrame frame = frames.get(index);
            if (!active.getAsBoolean() || !sink.canSend(frame)) {
                clearFrom(frames, index);
                return false;
            }
            try {
                sink.send(frame);
            } catch (RuntimeException exception) {
                clearFrom(frames, index);
                return false;
            }
            frame.clear();
        }
        return true;
    }

    private static void clearFrom(List<OutboundFrame> frames, int start) {
        for (int index = start; index < frames.size(); index++) {
            frames.get(index).clear();
        }
    }

    interface FrameSink {
        boolean canSend(OutboundFrame frame);

        void send(OutboundFrame frame);
    }
}
