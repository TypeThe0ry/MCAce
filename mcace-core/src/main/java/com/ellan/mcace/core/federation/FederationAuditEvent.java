package com.ellan.mcace.core.federation;

/** Fixed, content-free lifecycle events for operator review. */
public enum FederationAuditEvent {
    CONSENT_ISSUED,
    GRANT_SIGNED,
    PRESENTATION_ACCEPTED,
    PRESENTATION_REJECTED,
    GRANT_EXPIRED,
    SESSION_REMOVED,
    CONFIGURATION_RELOADED
}
