package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record StoredAuditAnchor(
        UUID anchorId,
        long sequence,
        Instant createdAt,
        long evidenceSequence,
        byte[] evidenceChainSha256,
        long revocationCount,
        long revocationMaxSequence,
        byte[] revocationFeedSha256,
        long operatorAuditCount,
        byte[] operatorAuditSha256,
        byte[] previousAnchorSha256,
        byte[] anchorSha256,
        byte[] serverSignature,
        String signerKeyId) {
    public StoredAuditAnchor {
        Objects.requireNonNull(anchorId, "anchorId");
        Objects.requireNonNull(createdAt, "createdAt");
        if (sequence <= 0 || evidenceSequence < 0 || revocationCount < 0
                || revocationMaxSequence < 0 || operatorAuditCount < 0) {
            throw new IllegalArgumentException("audit anchor sequences and counts are invalid");
        }
        if (revocationCount == 0 && revocationMaxSequence != 0) {
            throw new IllegalArgumentException("empty revocation feed cannot have a maximum sequence");
        }
        evidenceChainSha256 = hash(evidenceChainSha256, "evidenceChainSha256");
        revocationFeedSha256 = hash(revocationFeedSha256, "revocationFeedSha256");
        operatorAuditSha256 = hash(operatorAuditSha256, "operatorAuditSha256");
        previousAnchorSha256 = hash(previousAnchorSha256, "previousAnchorSha256");
        anchorSha256 = hash(anchorSha256, "anchorSha256");
        Objects.requireNonNull(serverSignature, "serverSignature");
        if (serverSignature.length != 64) {
            throw new IllegalArgumentException("audit anchor signature must contain 64 bytes");
        }
        serverSignature = serverSignature.clone();
        signerKeyId = bounded(signerKeyId, "signerKeyId", 128);
    }

    @Override public byte[] evidenceChainSha256() { return evidenceChainSha256.clone(); }
    @Override public byte[] revocationFeedSha256() { return revocationFeedSha256.clone(); }
    @Override public byte[] operatorAuditSha256() { return operatorAuditSha256.clone(); }
    @Override public byte[] previousAnchorSha256() { return previousAnchorSha256.clone(); }
    @Override public byte[] anchorSha256() { return anchorSha256.clone(); }
    @Override public byte[] serverSignature() { return serverSignature.clone(); }

    private static byte[] hash(byte[] value, String field) {
        Objects.requireNonNull(value, field);
        if (value.length != 32) {
            throw new IllegalArgumentException(field + " must contain 32 bytes");
        }
        return value.clone();
    }

    private static String bounded(String value, String field, int maximum) {
        Objects.requireNonNull(value, field);
        String normalized = value.strip();
        if (normalized.isEmpty() || normalized.length() > maximum) {
            throw new IllegalArgumentException(field + " must contain 1-" + maximum + " characters");
        }
        return normalized;
    }
}
