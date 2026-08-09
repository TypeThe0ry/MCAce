package com.ellan.mcace.core.persistence;

public final class SecurityPersistenceException extends Exception {
    private static final long serialVersionUID = 1L;

    public SecurityPersistenceException(String message, Throwable cause) {
        super(message, cause);
    }

    public SecurityPersistenceException(String message) {
        super(message);
    }
}
