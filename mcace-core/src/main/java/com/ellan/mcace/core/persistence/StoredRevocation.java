package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.Objects;

public record StoredRevocation(
        RevocationDraft revocation,
        long sequence,
        Instant createdAt,
        byte[] payloadSha256,
        byte[] serverSignature,
        String signerKeyId) {
    public StoredRevocation {
        Objects.requireNonNull(revocation, "revocation");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(payloadSha256, "payloadSha256");
        Objects.requireNonNull(serverSignature, "serverSignature");
        signerKeyId = Objects.requireNonNull(signerKeyId, "signerKeyId");
        if (sequence <= 0 || payloadSha256.length != 32 || serverSignature.length == 0
                || signerKeyId.isBlank()) {
            throw new IllegalArgumentException("invalid stored revocation");
        }
        payloadSha256 = payloadSha256.clone();
        serverSignature = serverSignature.clone();
    }

    @Override public byte[] payloadSha256() { return payloadSha256.clone(); }
    @Override public byte[] serverSignature() { return serverSignature.clone(); }
}
