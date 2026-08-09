package com.ellan.mcace.sdk;

/** Read-only lifecycle state for an MCAce session. @since 1.0 */
public enum SessionState {
    /** A connection has been observed but authentication is not complete. */
    CONNECTING,
    /** Authentication or policy evaluation is in progress. */
    VERIFYING,
    /** The session passed the currently applicable policy. */
    VERIFIED,
    /** The session remains present but is subject to a server-owned limitation. */
    LIMITED,
    /** The session was closed or denied by the server. */
    CLOSED
}
