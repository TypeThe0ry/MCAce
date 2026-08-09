package com.ellan.mcace.core.persistence;

public final class WorkflowConflictException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public enum Kind { NOT_FOUND, VERSION_MISMATCH, INVALID_TRANSITION, PLAYER_MISMATCH }

    private final Kind kind;

    public WorkflowConflictException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}
