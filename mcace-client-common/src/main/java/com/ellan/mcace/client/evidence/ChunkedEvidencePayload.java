package com.ellan.mcace.client.evidence;

import java.util.HexFormat;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Complete immutable description of a bounded evidence payload and its fragments. */
public record ChunkedEvidencePayload(
        long totalBytes, List<EvidencePayloadChunk> chunks, byte[] sha256, byte[] merkleRoot) {
    public ChunkedEvidencePayload {
        if (totalBytes <= 0) {
            throw new IllegalArgumentException("totalBytes must be positive");
        }
        chunks = List.copyOf(Objects.requireNonNull(chunks, "chunks"));
        Objects.requireNonNull(sha256, "sha256");
        Objects.requireNonNull(merkleRoot, "merkleRoot");
        if (chunks.isEmpty()) {
            throw new IllegalArgumentException("chunks must not be empty");
        }
        if (sha256.length != EvidencePayloadChunker.SHA_256_BYTES
                || merkleRoot.length != EvidencePayloadChunker.SHA_256_BYTES) {
            throw new IllegalArgumentException("hashes must contain 32 bytes");
        }
        long actualBytes = 0;
        for (int index = 0; index < chunks.size(); index++) {
            EvidencePayloadChunk chunk = chunks.get(index);
            if (chunk.index() != index) {
                throw new IllegalArgumentException("chunks must have contiguous indices");
            }
            actualBytes = Math.addExact(actualBytes, chunk.content().length);
        }
        if (actualBytes != totalBytes) {
            throw new IllegalArgumentException("totalBytes does not match chunks");
        }
        sha256 = sha256.clone();
        merkleRoot = merkleRoot.clone();
    }

    @Override
    public byte[] sha256() {
        return sha256.clone();
    }

    @Override
    public byte[] merkleRoot() {
        return merkleRoot.clone();
    }

    public String sha256Hex() {
        return HexFormat.of().formatHex(sha256);
    }

    public String merkleRootHex() {
        return HexFormat.of().formatHex(merkleRoot);
    }

    /** Clears the owned payload and hash buffers after transfer construction or cancellation. */
    public void clear() {
        chunks.forEach(EvidencePayloadChunk::clear);
        Arrays.fill(sha256, (byte) 0);
        Arrays.fill(merkleRoot, (byte) 0);
    }
}
