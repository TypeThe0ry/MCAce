package com.ellan.mcace.core.disposition;

/** Raised when a signed protobuf document cannot be represented without weakening its semantics. */
public final class DispositionPolicyCompileException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    public DispositionPolicyCompileException(String message) { super(message); }
    public DispositionPolicyCompileException(String message, Throwable cause) { super(message, cause); }
}
