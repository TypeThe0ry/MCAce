package com.ellan.mcace.sdk;

/** Lifecycle state for a content-free evidence summary. @since 1.0 */
public enum EvidenceState {
    /** Evidence was requested but no result has been received. */
    REQUESTED,
    /** The player declined or the client does not support the request. */
    DECLINED_OR_UNSUPPORTED,
    /** Content was received but has not completed server validation. */
    RECEIVED,
    /** Server validation completed. This does not itself establish misconduct. */
    VERIFIED,
    /** The configured retention window elapsed. */
    EXPIRED,
    /** An authorized retention workflow deleted the record. */
    DELETED
}
