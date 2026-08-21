package com.ellan.mcace.core.authority;

/** Fail-closed validation failure for the disabled-by-default backend authority protocol. */
public sealed class AuthorityProtocolException extends Exception
        permits AuthoritySequenceMismatchException {
    private static final long serialVersionUID = 1L;

    public AuthorityProtocolException(String message) {
        super(message);
    }

    public AuthorityProtocolException(String message, Throwable cause) {
        super(message, cause);
    }
}
