package com.ellan.mcace.core.proxy;

import java.util.Arrays;
import java.util.Objects;

/** Declared immutable dimensions for one client observation transfer. */
public record ObservationTransferStart(
        String transferId, long totalBytes, int totalChunks, byte[] contentSha256) {
    public ObservationTransferStart {
        Objects.requireNonNull(transferId, "transferId");
        Objects.requireNonNull(contentSha256, "contentSha256");
        if (!transferId.matches("[A-Za-z0-9_-]{16,128}") || totalBytes < 0 || totalChunks <= 0
                || contentSha256.length != 32) {
            throw new IllegalArgumentException("invalid observation transfer start");
        }
        contentSha256 = contentSha256.clone();
    }

    @Override
    public byte[] contentSha256() {
        return contentSha256.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ObservationTransferStart that
                && totalBytes == that.totalBytes && totalChunks == that.totalChunks
                && transferId.equals(that.transferId) && Arrays.equals(contentSha256, that.contentSha256);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(transferId, totalBytes, totalChunks) + Arrays.hashCode(contentSha256);
    }
}
