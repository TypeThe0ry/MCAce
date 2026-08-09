package com.ellan.mcace.core.federation;

/** Fixed operation status for proxy adapters; every non-success result is inert. */
public enum FederationRuntimeStatus {
    CONSENT_ISSUED,
    GRANT_READY,
    OBSERVED,
    DISABLED,
    NOT_PINNED,
    NO_CURRENT_SUBJECT,
    PENDING_EXISTS,
    NO_PENDING_REQUEST,
    CAPACITY_REACHED,
    INVALID_FRAME,
    INVALID_CONSENT,
    INVALID_PRESENTATION,
    REPLAYED,
    EXPIRED,
    AUDIT_FAILED,
    INTERNAL_ERROR
}
