package com.ellan.mcace.core.trust;

/**
 * Coarse connection trust state exposed to policy and operator surfaces.
 *
 * <p>This is deliberately separate from the wire {@code TrustLevel}: the wire level describes
 * the authentication result, while this state also accounts for freshness and corroborated
 * server-side findings.</p>
 */
public enum ClientTrustState {
    TRUSTED,
    UNTRUSTED,
    SUSPECT,
    BLOCKED,
    STALE
}
