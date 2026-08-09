package com.ellan.mcace.core.federation;

/** Explainable result code; none of these values is a local admission decision. */
public enum FederationAuditOutcome {
    SUCCEEDED,
    DISABLED,
    NOT_PINNED,
    NO_LOCAL_SESSION,
    NOT_LOCALLY_VERIFIED,
    INVALID_CONSENT,
    INVALID_PRESENTATION,
    AUDIT_FAILED,
    EXPIRED,
    REPLAYED,
    CAPACITY_REACHED,
    CANCELLED
}
