package com.ellan.mcace.sdk;

/** Availability state for the optional content-free evidence-summary API. @since 1.0 */
public enum EvidenceSummaryAvailability {
    /** The API implementation did not opt into evidence-summary publication. */
    NOT_SUPPORTED,
    /** Evidence summaries are supported but no matching records exist. */
    AVAILABLE,
    /** Evidence summaries are available only to an explicitly authorized server-side caller. */
    NOT_AUTHORIZED
}
