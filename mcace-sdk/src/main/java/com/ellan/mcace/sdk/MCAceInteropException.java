package com.ellan.mcace.sdk;

/** Signals a malformed or unavailable cross-class-loader MCAce interop response. @since 1.0 */
public final class MCAceInteropException extends IllegalStateException {
    private static final long serialVersionUID = 1L;

    /** Creates an exception with a diagnostic message. */
    public MCAceInteropException(String message) {
        super(message);
    }

    /** Creates an exception with a diagnostic message and cause. */
    public MCAceInteropException(String message, Throwable cause) {
        super(message, cause);
    }
}
