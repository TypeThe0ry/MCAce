package com.ellan.mcace.core.persistence;

import java.time.Instant;
import java.util.Objects;

public record StoredEvidenceMetadata(
        EvidenceMetadataDraft evidence,
        long chainSequence,
        Instant storedAt,
        byte[] previousChainSha256,
        byte[] chainSha256,
        byte[] serverSignature,
        String signerKeyId) {
    public StoredEvidenceMetadata {
        Objects.requireNonNull(evidence, "evidence");
        Objects.requireNonNull(storedAt, "storedAt");
        Objects.requireNonNull(previousChainSha256, "previousChainSha256");
        Objects.requireNonNull(chainSha256, "chainSha256");
        Objects.requireNonNull(serverSignature, "serverSignature");
        signerKeyId = Objects.requireNonNull(signerKeyId, "signerKeyId");
        if (chainSequence <= 0 || previousChainSha256.length != 32 || chainSha256.length != 32
                || serverSignature.length == 0 || signerKeyId.isBlank()) {
            throw new IllegalArgumentException("invalid stored evidence metadata");
        }
        previousChainSha256 = previousChainSha256.clone();
        chainSha256 = chainSha256.clone();
        serverSignature = serverSignature.clone();
    }

    @Override public byte[] previousChainSha256() { return previousChainSha256.clone(); }
    @Override public byte[] chainSha256() { return chainSha256.clone(); }
    @Override public byte[] serverSignature() { return serverSignature.clone(); }
}
