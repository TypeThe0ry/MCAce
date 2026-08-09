package com.ellan.mcace.core.proxy;

/** Invalid client observation payload; it is observational and never an admission instruction. */
public final class ObservationPayloadException extends Exception {
    private static final long serialVersionUID = 1L;
    public ObservationPayloadException(String message) { super(message); }
    public ObservationPayloadException(String message, Throwable cause) { super(message, cause); }
}
