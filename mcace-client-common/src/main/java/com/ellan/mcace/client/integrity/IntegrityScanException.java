package com.ellan.mcace.client.integrity;

public final class IntegrityScanException extends Exception {
    private static final long serialVersionUID = 1L;

    public IntegrityScanException(String message) {
        super(message);
    }

    public IntegrityScanException(String message, Throwable cause) {
        super(message, cause);
    }
}
