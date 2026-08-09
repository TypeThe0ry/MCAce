package com.ellan.mcace.sdk;

/** Read-only admission state published by MCAce. @since 1.0 */
public enum AdmissionStatus {
    CONNECTING,
    VERIFYING,
    VERIFIED,
    LIMITED,
    BLOCKED
}
