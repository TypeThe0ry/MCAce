package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.Objects;

public record StoredRiskPolicyRelease(
        RiskPolicyReleaseDraft draft,
        Instant createdAt,
        byte[] releaseSha256) {
    public StoredRiskPolicyRelease {
        Objects.requireNonNull(draft, "draft");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(releaseSha256, "releaseSha256");
        if (releaseSha256.length != 32) throw new IllegalArgumentException("invalid release digest");
        releaseSha256 = releaseSha256.clone();
    }
    @Override public byte[] releaseSha256() { return releaseSha256.clone(); }
}
