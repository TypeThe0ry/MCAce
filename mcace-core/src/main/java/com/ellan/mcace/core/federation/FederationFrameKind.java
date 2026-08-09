package com.ellan.mcace.core.federation;

/** Pre-routing classification only; it is never proof that a frame is authentic. */
public enum FederationFrameKind {
    NOT_FEDERATION,
    CLIENT_CONSENT_RESPONSE,
    CLIENT_PRESENTATION,
    SERVER_ONLY,
    MALFORMED
}
