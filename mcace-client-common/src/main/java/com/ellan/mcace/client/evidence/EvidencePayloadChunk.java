package com.ellan.mcace.client.evidence;

import java.util.HexFormat;
import java.util.Arrays;
import java.util.Objects;

/** A single immutable, integrity-addressed evidence payload fragment. */
public record EvidencePayloadChunk(int index, byte[] content, byte[] sha256) {
    public EvidencePayloadChunk {
        if (index < 0) {
            throw new IllegalArgumentException("index must not be negative");
        }
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(sha256, "sha256");
        if (content.length == 0) {
            throw new IllegalArgumentException("content must not be empty");
        }
        if (sha256.length != EvidencePayloadChunker.SHA_256_BYTES) {
            throw new IllegalArgumentException("sha256 must contain 32 bytes");
        }
        content = content.clone();
        sha256 = sha256.clone();
    }

    @Override
    public byte[] content() {
        return content.clone();
    }

    @Override
    public byte[] sha256() {
        return sha256.clone();
    }

    public String sha256Hex() {
        return HexFormat.of().formatHex(sha256);
    }

    /** Clears the owned fragment buffers after the signed transfer has been built or cancelled. */
    public void clear() {
        Arrays.fill(content, (byte) 0);
        Arrays.fill(sha256, (byte) 0);
    }
}
