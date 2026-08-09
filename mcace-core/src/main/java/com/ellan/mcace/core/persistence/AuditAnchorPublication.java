package com.ellan.mcace.core.persistence;

import java.net.URI;
import java.time.Instant;
import java.util.Objects;

public record AuditAnchorPublication(
        URI destination,
        Instant publishedAt,
        String receiptReference,
        byte[] receiptSha256) {
    public AuditAnchorPublication {
        Objects.requireNonNull(destination, "destination");
        Objects.requireNonNull(publishedAt, "publishedAt");
        Objects.requireNonNull(receiptReference, "receiptReference");
        receiptReference = receiptReference.strip();
        if (receiptReference.isEmpty() || receiptReference.length() > 256) {
            throw new IllegalArgumentException("receiptReference must contain 1-256 characters");
        }
        Objects.requireNonNull(receiptSha256, "receiptSha256");
        if (receiptSha256.length != 32) {
            throw new IllegalArgumentException("receiptSha256 must contain 32 bytes");
        }
        receiptSha256 = receiptSha256.clone();
    }

    @Override public byte[] receiptSha256() { return receiptSha256.clone(); }
}
