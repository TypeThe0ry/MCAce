package com.ellan.mcace.core.evidence;

import java.time.Instant;
import java.util.Objects;

/** Decrypted in-memory artifact; callers must keep its lifetime short and clear working copies. */
public record EvidenceReviewArtifact(
        EvidenceStorageMetadata metadata, Instant expiresAt, byte[] content, int storageFormatVersion) {
    /** Compatibility constructor for the current self-describing encrypted evidence format. */
    public EvidenceReviewArtifact(EvidenceStorageMetadata metadata, Instant expiresAt, byte[] content) {
        this(metadata, expiresAt, content, 2);
    }

    public EvidenceReviewArtifact {
        Objects.requireNonNull(metadata, "metadata");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(content, "content");
        if (!expiresAt.isAfter(metadata.capturedAt()) || content.length == 0
                || storageFormatVersion < 1 || storageFormatVersion > 2) {
            throw new IllegalArgumentException("invalid review artifact");
        }
        content = content.clone();
    }

    @Override public byte[] content() { return content.clone(); }
}
