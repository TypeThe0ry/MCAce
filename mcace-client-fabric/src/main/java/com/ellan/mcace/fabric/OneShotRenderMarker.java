package com.ellan.mcace.fabric;

import java.util.Objects;

/** Emits a content-free UI lifecycle callback after the first completed render only. */
final class OneShotRenderMarker {
    private final Runnable callback;
    private boolean emitted;
    private long renderedAtNanos;

    OneShotRenderMarker(Runnable callback) {
        this.callback = Objects.requireNonNull(callback, "callback");
    }

    void markRendered() {
        markRendered(System.nanoTime());
    }

    void markRendered(long nowNanos) {
        if (emitted) {
            return;
        }
        emitted = true;
        renderedAtNanos = nowNanos;
        callback.run();
    }

    /** True once the first render completed at least {@code delayNanos} before {@code nowNanos}. */
    boolean renderedFor(long nowNanos, long delayNanos) {
        return emitted && nowNanos - renderedAtNanos >= delayNanos;
    }

    boolean emitted() {
        return emitted;
    }
}
