package com.ellan.mcace.cloud.anchor;

public final class AuditAnchorPublicationException extends Exception {
    private static final long serialVersionUID = 1L;

    public AuditAnchorPublicationException(String message) {
        super(message);
    }

    public AuditAnchorPublicationException(String message, Throwable cause) {
        super(message, cause);
    }
}
