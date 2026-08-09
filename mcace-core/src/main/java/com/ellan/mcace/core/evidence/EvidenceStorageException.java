package com.ellan.mcace.core.evidence;

/** Fail-closed storage error; it never contains raw evidence or key material. */
public final class EvidenceStorageException extends java.io.IOException {
    private static final long serialVersionUID = 1L;
    public EvidenceStorageException(String message) { super(message); }
    public EvidenceStorageException(String message, Throwable cause) { super(message, cause); }
}
