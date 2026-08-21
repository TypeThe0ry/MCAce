package com.ellan.mcace.core.context;

/** A bounded backend-context frame failed structural or freshness validation. */
public final class BackendContextException extends Exception {
    private static final long serialVersionUID = 1L;

    public BackendContextException(String message) {
        super(message);
    }

    public BackendContextException(String message, Throwable cause) {
        super(message, cause);
    }
}
