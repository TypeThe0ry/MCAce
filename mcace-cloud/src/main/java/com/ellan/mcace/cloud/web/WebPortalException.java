package com.ellan.mcace.cloud.web;

public final class WebPortalException extends Exception {
    public enum Kind {
        INVALID_HANDOFF,
        INVALID_SESSION,
        CSRF_REJECTED
    }

    private static final long serialVersionUID = 1L;
    private final Kind kind;

    public WebPortalException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}
