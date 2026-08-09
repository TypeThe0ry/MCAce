package com.ellan.mcace.sdk;

import java.util.EnumSet;
import java.util.Set;

/** Read-only feature that an {@link MCAceApi} implementation can explicitly offer. @since 1.0 */
public enum MCAceCapability {
    /** Immutable player snapshots are available. */
    PLAYER_SECURITY_SNAPSHOT,
    /** Trust summaries derived from snapshots are available. */
    TRUST_SUMMARY,
    /** Risk summaries derived from snapshots are available. */
    RISK_SUMMARY,
    /** Non-sensitive active-session metadata is available. */
    SESSION_SUMMARY,
    /** Content-free evidence metadata is available. */
    EVIDENCE_SUMMARY;

    /**
     * Returns capabilities guaranteed by the original snapshot-only API.
     *
     * @return immutable baseline capability set
     */
    public static Set<MCAceCapability> baseline() {
        return Set.copyOf(EnumSet.of(PLAYER_SECURITY_SNAPSHOT, TRUST_SUMMARY, RISK_SUMMARY));
    }
}
