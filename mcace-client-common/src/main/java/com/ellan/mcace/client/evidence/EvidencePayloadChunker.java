package com.ellan.mcace.client.evidence;

import com.ellan.mcace.protocol.ProtocolConstants;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Splits an already-authorized in-memory payload into bounded, hash-addressed fragments.
 * This class never captures, persists, or logs evidence content.
 */
public final class EvidencePayloadChunker {
    public static final int SHA_256_BYTES = 32;

    public record Limits(int maxChunkBytes, long maxTotalBytes, int maxChunks) {
        public Limits {
            if (maxChunkBytes <= 0 || maxTotalBytes <= 0 || maxChunks <= 0) {
                throw new IllegalArgumentException("all limits must be positive");
            }
        }

        public static Limits protocolDefaults() {
            return new Limits(
                    ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES,
                    ProtocolConstants.MAX_EVIDENCE_TOTAL_BYTES,
                    ProtocolConstants.MAX_EVIDENCE_CHUNKS);
        }
    }

    public ChunkedEvidencePayload chunk(byte[] payload, Limits limits) {
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(limits, "limits");
        if (payload.length == 0) {
            throw new IllegalArgumentException("payload must not be empty");
        }
        long totalBytes = payload.length;
        if (totalBytes > limits.maxTotalBytes()) {
            throw new IllegalArgumentException("payload exceeds maxTotalBytes");
        }
        long requiredChunks = ((totalBytes - 1L) / limits.maxChunkBytes()) + 1L;
        if (requiredChunks > limits.maxChunks() || requiredChunks > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("payload requires too many chunks");
        }

        List<EvidencePayloadChunk> chunks = new ArrayList<>((int) requiredChunks);
        for (int offset = 0, index = 0; offset < payload.length; index++) {
            int length = Math.min(limits.maxChunkBytes(), payload.length - offset);
            byte[] content = new byte[length];
            System.arraycopy(payload, offset, content, 0, length);
            chunks.add(new EvidencePayloadChunk(index, content, sha256(content)));
            offset = Math.addExact(offset, length);
        }
        return new ChunkedEvidencePayload(totalBytes, chunks, sha256(payload), merkleRoot(chunks));
    }

    public ChunkedEvidencePayload chunk(byte[] payload, int maxChunkBytes, long maxTotalBytes, int maxChunks) {
        return chunk(payload, new Limits(maxChunkBytes, maxTotalBytes, maxChunks));
    }

    private static byte[] merkleRoot(List<EvidencePayloadChunk> chunks) {
        List<byte[]> level = new ArrayList<>(chunks.size());
        for (EvidencePayloadChunk chunk : chunks) {
            level.add(chunk.sha256());
        }
        while (level.size() > 1) {
            List<byte[]> nextLevel = new ArrayList<>((level.size() + 1) / 2);
            for (int index = 0; index < level.size(); index += 2) {
                byte[] left = level.get(index);
                byte[] right = index + 1 < level.size() ? level.get(index + 1) : left;
                MessageDigest digest = newSha256();
                digest.update(left);
                nextLevel.add(digest.digest(right));
            }
            level = nextLevel;
        }
        return level.getFirst().clone();
    }

    private static byte[] sha256(byte[] content) {
        return newSha256().digest(content);
    }

    private static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", exception);
        }
    }
}
