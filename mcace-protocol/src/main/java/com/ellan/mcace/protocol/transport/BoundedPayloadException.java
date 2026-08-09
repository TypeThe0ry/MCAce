package com.ellan.mcace.protocol.transport;

/** Rejected bounded transfer state; callers must not treat this as a punishment signal. */
public final class BoundedPayloadException extends Exception {
    private static final long serialVersionUID = 1L;
    public BoundedPayloadException(String message) { super(message); }
    public BoundedPayloadException(String message, Throwable cause) { super(message, cause); }
}
