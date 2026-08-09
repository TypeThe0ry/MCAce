package com.ellan.mcace.protocol.federation;

public final class FederationException extends Exception {
    private static final long serialVersionUID = 1L;

    public FederationException(String message) {
        super(message);
    }

    public FederationException(String message, Throwable cause) {
        super(message, cause);
    }
}
