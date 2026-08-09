package com.ellan.mcace.protocol.crypto;

public final class EnvelopeException extends Exception {
    private static final long serialVersionUID = 1L;

    public EnvelopeException(String message) {
        super(message);
    }

    public EnvelopeException(String message, Throwable cause) {
        super(message, cause);
    }
}
