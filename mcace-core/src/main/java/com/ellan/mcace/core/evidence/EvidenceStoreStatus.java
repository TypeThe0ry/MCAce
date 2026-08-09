package com.ellan.mcace.core.evidence;

import java.util.Objects;

/** Bounded, content-free administrative status. */
public record EvidenceStoreStatus(
        boolean enabled, String state, long fileCount, long totalBytes,
        long maxFiles, long maxTotalBytes, long retentionSeconds, String retentionPolicyId) {
    public EvidenceStoreStatus {
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(retentionPolicyId, "retentionPolicyId");
        if (state.isBlank() || state.length() > 64 || retentionPolicyId.length() > 128
                || fileCount < 0 || totalBytes < 0 || maxFiles < 0 || maxTotalBytes < 0
                || retentionSeconds < 0) {
            throw new IllegalArgumentException("invalid evidence store status");
        }
    }

    public static EvidenceStoreStatus disabled(String reason) {
        return new EvidenceStoreStatus(false, reason, 0, 0, 0, 0, 0, "");
    }
}
