package com.ellan.mcace.fabric;

import com.ellan.mcace.client.session.ClientHandshakeEngine.VerifiedEvidenceRequest;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Clock;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.imageio.ImageIO;
import net.minecraft.client.MinecraftClient;
import net.minecraft.client.gl.Framebuffer;
import net.minecraft.client.texture.NativeImage;
import net.minecraft.client.util.ScreenshotRecorder;
import net.minecraft.client.gui.screen.Screen;

/**
 * Fabric-only evidence lifecycle. The render callback copies pixels and immediately releases the
 * NativeImage; encoding and all protocol work run on a virtual-thread executor. No filesystem or
 * operating-system capture API is used here.
 */
final class EvidenceCaptureController implements AutoCloseable {
    interface Sender {
        void sendOutcome(VerifiedEvidenceRequest request, EvidenceCollectionStatus status);

        void sendFrame(VerifiedEvidenceRequest request, long capturedAtEpochMs,
                int widthPixels, int heightPixels, byte[] encodedContent);

        void cancel(VerifiedEvidenceRequest request);

        default void screenRendered(VerifiedEvidenceRequest request) { }

        default void consentAllowed(VerifiedEvidenceRequest request) { }
    }

    private enum State { CONSENT, ARMED, CAPTURING, ENCODING }

    private final Clock clock;
    private final ExecutorService encoder = Executors.newVirtualThreadPerTaskExecutor();
    private Pending pending;

    EvidenceCaptureController(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    void accept(MinecraftClient client, VerifiedEvidenceRequest request, Sender sender) {
        Objects.requireNonNull(client, "client");
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(sender, "sender");
        cancelPending(client, true);
        if (request.captureScope() != EvidenceCaptureScope.GAME_RENDER_FRAME) {
            sender.sendOutcome(request, EvidenceCollectionStatus.EVIDENCE_COLLECTION_UNAVAILABLE);
            return;
        }
        if (request.expiredAt(clock.millis())) {
            sender.sendOutcome(request, EvidenceCollectionStatus.EVIDENCE_COLLECTION_EXPIRED);
            return;
        }
        Pending next = new Pending(client, request, sender, client.currentScreen, State.CONSENT);
        pending = next;
        client.setScreen(new EvidenceConsentScreen(
                next.previous(), request, () -> sender.screenRendered(request),
                allowed -> decide(next, allowed)));
    }

    void tick(MinecraftClient client) {
        Pending current = pending;
        if (current == null || current.client() != client) {
            return;
        }
        if ((current.state() == State.CONSENT || current.state() == State.ARMED
                || current.state() == State.CAPTURING)
                && current.request().expiredAt(clock.millis())) {
            finishOutcome(client, current, EvidenceCollectionStatus.EVIDENCE_COLLECTION_EXPIRED);
        }
    }

    /** Must be called from Fabric's WorldRenderEvents.END_MAIN callback. */
    void captureAtEndOfWorldRender(MinecraftClient client) {
        Pending current = pending;
        if (current == null || current.client() != client || current.state() != State.ARMED) {
            return;
        }
        if (current.request().expiredAt(clock.millis())) {
            finishOutcome(client, current, EvidenceCollectionStatus.EVIDENCE_COLLECTION_EXPIRED);
            return;
        }
        if (!current.matchesArmedSize(framebufferSize(client))) {
            finishOutcome(client, current, EvidenceCollectionStatus.EVIDENCE_COLLECTION_FAILED);
            return;
        }
        current.state(State.CAPTURING);
        final long capturedAt = clock.millis();
        try {
            ScreenshotRecorder.takeScreenshot(client.getFramebuffer(),
                    image -> receiveRenderedFrame(client, current, capturedAt, image));
        } catch (RuntimeException exception) {
            if (isCurrentConsentGeneration(pending, current) && current.state() == State.CAPTURING) {
                finishOutcome(client, current, EvidenceCollectionStatus.EVIDENCE_COLLECTION_FAILED);
            }
        }
    }

    private void receiveRenderedFrame(MinecraftClient client, Pending current,
            long capturedAt, NativeImage image) {
        FrameCopy copy = null;
        EvidenceCollectionStatus failure = null;
        try (image) {
            if (!isCurrentConsentGeneration(pending, current) || current.state() != State.CAPTURING) {
                return;
            }
            if (current.request().expiredAt(clock.millis())) {
                failure = EvidenceCollectionStatus.EVIDENCE_COLLECTION_EXPIRED;
            } else {
                copy = copyRenderedFrame(image);
                if (!current.matchesArmedSize(new FramebufferSize(copy.width(), copy.height()))) {
                    copy.clear();
                    copy = null;
                    failure = EvidenceCollectionStatus.EVIDENCE_COLLECTION_FAILED;
                }
            }
        } catch (RuntimeException exception) {
            if (copy != null) {
                copy.clear();
                copy = null;
            }
            failure = EvidenceCollectionStatus.EVIDENCE_COLLECTION_FAILED;
        }
        if (!isCurrentConsentGeneration(pending, current) || current.state() != State.CAPTURING) {
            if (copy != null) {
                copy.clear();
            }
            return;
        }
        if (failure != null) {
            finishOutcome(client, current, failure);
            return;
        }
        current.state(State.ENCODING);
        current.frameCopy(copy);
        submitEncoding(client, current, capturedAt, copy);
    }

    private void submitEncoding(MinecraftClient client, Pending current,
            long capturedAt, FrameCopy copy) {
        try {
            encoder.submit(() -> {
                byte[] encoded = null;
                try {
                    encoded = encodePng(copy);
                    final byte[] delivered = encoded;
                    client.execute(() -> finishContent(
                            client, current, capturedAt, copy.width(), copy.height(), delivered));
                    encoded = null;
                } catch (RuntimeException exception) {
                    if (encoded != null) {
                        Arrays.fill(encoded, (byte) 0);
                    }
                    try {
                        client.execute(() -> finishOutcome(
                                client, current, EvidenceCollectionStatus.EVIDENCE_COLLECTION_FAILED));
                    } catch (RuntimeException ignored) {
                        current.sender().cancel(current.request());
                    }
                } finally {
                    current.clearFrameCopy(copy);
                }
            });
        } catch (RuntimeException exception) {
            current.clearSensitive();
            finishOutcome(client, current, EvidenceCollectionStatus.EVIDENCE_COLLECTION_FAILED);
        }
    }

    void cancel(MinecraftClient client) {
        cancelPending(client, false);
    }

    @Override
    public void close() {
        Pending current = pending;
        pending = null;
        if (current != null) {
            current.clearSensitive();
            current.sender().cancel(current.request());
        }
        encoder.shutdownNow();
    }

    private void decide(Pending current, boolean allowed) {
        if (!isCurrentConsentGeneration(pending, current) || current.state() != State.CONSENT) {
            return;
        }
        MinecraftClient client = current.client();
        client.setScreen(current.previous());
        if (!allowed) {
            finishOutcome(client, current, EvidenceCollectionStatus.EVIDENCE_COLLECTION_DECLINED);
            return;
        }
        current.sender().consentAllowed(current.request());
        if (current.request().expiredAt(clock.millis())) {
            finishOutcome(client, current, EvidenceCollectionStatus.EVIDENCE_COLLECTION_EXPIRED);
            return;
        }
        FramebufferSize size = framebufferSize(client);
        if (!size.valid()) {
            finishOutcome(client, current, EvidenceCollectionStatus.EVIDENCE_COLLECTION_FAILED);
            return;
        }
        current.arm(size);
        current.state(State.ARMED);
    }

    private void finishContent(MinecraftClient client, Pending current, long capturedAt,
            int width, int height, byte[] encoded) {
        if (!isCurrentConsentGeneration(pending, current) || current.state() != State.ENCODING) {
            Arrays.fill(encoded, (byte) 0);
            current.clearSensitive();
            current.sender().cancel(current.request());
            return;
        }
        pending = null;
        if (current.request().expiredAt(clock.millis())) {
            Arrays.fill(encoded, (byte) 0);
            current.sender().sendOutcome(current.request(), EvidenceCollectionStatus.EVIDENCE_COLLECTION_EXPIRED);
            return;
        }
        try {
            current.sender().sendFrame(current.request(), capturedAt, width, height, encoded);
        } catch (RuntimeException exception) {
            Arrays.fill(encoded, (byte) 0);
            current.sender().cancel(current.request());
        }
    }

    private void finishOutcome(MinecraftClient client, Pending current, EvidenceCollectionStatus status) {
        if (!isCurrentConsentGeneration(pending, current)) {
            current.clearSensitive();
            current.sender().cancel(current.request());
            return;
        }
        pending = null;
        current.clearSensitive();
        client.setScreen(current.previous());
        current.sender().sendOutcome(current.request(), status);
    }

    private void cancelPending(MinecraftClient client, boolean reportDecline) {
        Pending current = pending;
        if (current == null) {
            return;
        }
        pending = null;
        current.clearSensitive();
        if (client.currentScreen instanceof EvidenceConsentScreen consent
                && consent.previous() == current.previous()) {
            client.setScreen(current.previous());
        }
        if (reportDecline) {
            current.sender().sendOutcome(current.request(), EvidenceCollectionStatus.EVIDENCE_COLLECTION_DECLINED);
        } else {
            current.sender().cancel(current.request());
        }
    }

    /** Identity-based generation gate for callbacks that outlive a replaced consent request. */
    static boolean isCurrentConsentGeneration(Object active, Object candidate) {
        return active != null && active == candidate;
    }

    static boolean isStableFramebuffer(int expectedWidth, int expectedHeight,
            int currentWidth, int currentHeight) {
        return expectedWidth > 0 && expectedHeight > 0
                && currentWidth > 0 && currentHeight > 0
                && (long) currentWidth * currentHeight <= ProtocolConstants.MAX_EVIDENCE_PIXELS
                && expectedWidth == currentWidth && expectedHeight == currentHeight;
    }

    private static FrameCopy copyRenderedFrame(NativeImage image) {
        int width = image.getWidth();
        int height = image.getHeight();
        long pixels = (long) width * height;
        if (width <= 0 || height <= 0 || pixels > ProtocolConstants.MAX_EVIDENCE_PIXELS) {
            throw new IllegalArgumentException("render frame exceeds pixel bound");
        }
        int[] argb = image.copyPixelsArgb();
        if (argb.length != Math.multiplyExact(width, height)) {
            Arrays.fill(argb, 0);
            throw new IllegalStateException("render frame pixel count changed during capture");
        }
        return new FrameCopy(width, height, argb);
    }

    private static FramebufferSize framebufferSize(MinecraftClient client) {
        return new FramebufferSize(
                client.getWindow().getFramebufferWidth(),
                client.getWindow().getFramebufferHeight());
    }

    private static byte[] encodePng(FrameCopy copy) {
        BufferedImage image = null;
        try {
            image = new BufferedImage(copy.width(), copy.height(), BufferedImage.TYPE_INT_ARGB);
            image.setRGB(0, 0, copy.width(), copy.height(), copy.argb(), 0, copy.width());
            try (BoundedByteArrayOutputStream output = new BoundedByteArrayOutputStream(
                    Math.toIntExact(ProtocolConstants.MAX_EVIDENCE_TOTAL_BYTES))) {
                if (!ImageIO.write(image, "png", output)) {
                    throw new IllegalStateException("PNG encoder is unavailable");
                }
                return output.toByteArray();
            }
        } catch (IOException exception) {
            throw new IllegalStateException("in-memory PNG encoding failed", exception);
        } finally {
            if (image != null) {
                image.flush();
            }
            copy.clear();
        }
    }

    private static final class Pending {
        private final MinecraftClient client;
        private final VerifiedEvidenceRequest request;
        private final Sender sender;
        private final Screen previous;
        private State state;
        private int armedWidth;
        private int armedHeight;
        private FrameCopy frameCopy;

        private Pending(MinecraftClient client, VerifiedEvidenceRequest request, Sender sender,
                Screen previous, State state) {
            this.client = client;
            this.request = request;
            this.sender = sender;
            this.previous = previous;
            this.state = state;
        }

        private MinecraftClient client() { return client; }
        private VerifiedEvidenceRequest request() { return request; }
        private Sender sender() { return sender; }
        private Screen previous() { return previous; }
        private State state() { return state; }
        private void state(State value) { state = value; }

        private void arm(FramebufferSize size) {
            armedWidth = size.width();
            armedHeight = size.height();
        }

        private boolean matchesArmedSize(FramebufferSize size) {
            return isStableFramebuffer(armedWidth, armedHeight, size.width(), size.height());
        }

        private void frameCopy(FrameCopy value) { frameCopy = value; }

        private void clearFrameCopy(FrameCopy value) {
            if (frameCopy == value) {
                frameCopy = null;
            }
            value.clear();
        }

        private void clearSensitive() {
            if (frameCopy != null) {
                frameCopy.clear();
                frameCopy = null;
            }
        }
    }

    private record FrameCopy(int width, int height, int[] argb) {
        private void clear() {
            Arrays.fill(argb, 0);
        }
    }

    private record FramebufferSize(int width, int height) {
        private boolean valid() {
            return width > 0 && height > 0
                    && (long) width * height <= ProtocolConstants.MAX_EVIDENCE_PIXELS;
        }
    }

    private static final class BoundedByteArrayOutputStream extends ByteArrayOutputStream {
        private final int maxBytes;

        private BoundedByteArrayOutputStream(int maxBytes) {
            this.maxBytes = maxBytes;
        }

        @Override
        public synchronized void write(int value) {
            ensureCapacity(1);
            super.write(value);
        }

        @Override
        public synchronized void write(byte[] bytes, int offset, int length) {
            ensureCapacity(length);
            super.write(bytes, offset, length);
        }

        private void ensureCapacity(int length) {
            if (length < 0 || count > maxBytes - length) {
                throw new IllegalArgumentException("encoded evidence exceeds byte bound");
            }
        }
    }
}
