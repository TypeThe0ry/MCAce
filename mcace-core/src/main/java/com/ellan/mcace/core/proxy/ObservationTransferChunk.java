package com.ellan.mcace.core.proxy;

import java.util.Arrays;
import java.util.Objects;

/** A strictly ordered content chunk and its independent SHA-256. */
public record ObservationTransferChunk(String transferId, int index, byte[] content, byte[] contentSha256) {
    public ObservationTransferChunk {
        Objects.requireNonNull(transferId, "transferId");
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(contentSha256, "contentSha256");
        if (!transferId.matches("[A-Za-z0-9_-]{16,128}") || index < 0 || contentSha256.length != 32) {
            throw new IllegalArgumentException("invalid observation transfer chunk");
        }
        content = content.clone();
        contentSha256 = contentSha256.clone();
    }

    @Override public byte[] content() { return content.clone(); }
    @Override public byte[] contentSha256() { return contentSha256.clone(); }
    @Override public boolean equals(Object other) {
        return other instanceof ObservationTransferChunk that && index == that.index
                && transferId.equals(that.transferId) && Arrays.equals(content, that.content)
                && Arrays.equals(contentSha256, that.contentSha256);
    }
    @Override public int hashCode() {
        return 31 * Objects.hash(transferId, index) + 31 * Arrays.hashCode(content) + Arrays.hashCode(contentSha256);
    }
}
