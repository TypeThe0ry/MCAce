package com.ellan.mcace.core.proxy;

/**
 * Explains whether a refresh changed the active policy.  A rejected document never replaces a
 * known-good policy; when no valid policy exists, callers receive the safe OBSERVE default.
 */
public enum ProxyPolicyRefreshStatus {
    ACTIVE,
    REJECTED_INVALID,
    REJECTED_ROLLBACK,
    REJECTED_EQUIVOCATION,
    OBSERVE_NO_VALID_POLICY
}
