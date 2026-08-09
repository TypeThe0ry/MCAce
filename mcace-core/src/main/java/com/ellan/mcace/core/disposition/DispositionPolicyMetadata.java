package com.ellan.mcace.core.disposition;

import java.time.Instant;
import java.util.Objects;

/** Signed-document identity and rollout information retained with a compiled policy. */
public record DispositionPolicyMetadata(String policyId, long schemaVersion, long sequence, Instant issuedAt,
                                        Instant effectiveFrom, Instant expiresAt, String rolloutStage,
                                        String signerKeyIdSha256) {
    public DispositionPolicyMetadata {
        Objects.requireNonNull(policyId, "policyId"); Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(effectiveFrom, "effectiveFrom"); Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(rolloutStage, "rolloutStage"); Objects.requireNonNull(signerKeyIdSha256, "signerKeyIdSha256");
        if (policyId.isBlank() || rolloutStage.isBlank() || signerKeyIdSha256.length() != 64
                || schemaVersion <= 0 || sequence <= 0 || effectiveFrom.isBefore(issuedAt)
                || !expiresAt.isAfter(effectiveFrom)) {
            throw new IllegalArgumentException("invalid disposition policy metadata");
        }
    }
}
