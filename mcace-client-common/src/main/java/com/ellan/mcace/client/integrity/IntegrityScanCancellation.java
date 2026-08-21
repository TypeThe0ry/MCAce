package com.ellan.mcace.client.integrity;

/** Connection-bound cancellation probe checked before every file open and buffered read. */
@FunctionalInterface
public interface IntegrityScanCancellation {
    IntegrityScanCancellation NONE = () -> false;

    boolean cancelled();

    default void check() throws IntegrityScanException {
        if (cancelled() || Thread.currentThread().isInterrupted()) {
            throw new IntegrityScanException("integrity scan was cancelled");
        }
    }
}
