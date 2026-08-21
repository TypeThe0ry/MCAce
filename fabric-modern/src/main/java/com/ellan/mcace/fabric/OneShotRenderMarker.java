package com.ellan.mcace.fabric;

import java.util.Objects;

/** Emits a content-free UI lifecycle callback after the first completed render only. */
final class OneShotRenderMarker {
    private final Runnable callback;
    private boolean emitted;

    OneShotRenderMarker(Runnable callback) {
        this.callback = Objects.requireNonNull(callback, "callback");
    }

    void markRendered() {
        if (emitted) {
            return;
        }
        emitted = true;
        callback.run();
    }

    boolean emitted() {
        return emitted;
    }
}
