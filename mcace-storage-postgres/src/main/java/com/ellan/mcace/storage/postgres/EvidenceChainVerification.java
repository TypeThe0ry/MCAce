package com.ellan.mcace.storage.postgres;

import java.util.Objects;

public record EvidenceChainVerification(
        boolean valid,
        long verifiedEntries,
        long firstInvalidSequence,
        String reason) {
    public EvidenceChainVerification {
        reason = Objects.requireNonNull(reason, "reason");
        if (verifiedEntries < 0 || firstInvalidSequence < 0 || reason.isBlank()) {
            throw new IllegalArgumentException("invalid evidence chain verification result");
        }
    }

    static EvidenceChainVerification valid(long entries) {
        return new EvidenceChainVerification(true, entries, 0, "valid");
    }

    static EvidenceChainVerification invalid(long verified, long sequence, String reason) {
        return new EvidenceChainVerification(false, verified, sequence, reason);
    }
}
