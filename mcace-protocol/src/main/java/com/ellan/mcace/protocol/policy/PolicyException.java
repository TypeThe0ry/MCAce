package com.ellan.mcace.protocol.policy;

public final class PolicyException extends Exception {
    private static final long serialVersionUID = 1L;

    public PolicyException(String message) {
        super(message);
    }

    public PolicyException(String message, Throwable cause) {
        super(message, cause);
    }
}
