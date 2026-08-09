package com.ellan.mcace.protocol.transport;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.BoundedPayloadKind;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/** Shared size, hash, and Merkle invariants for proxy-safe fragmented protocol payloads. */
public final class BoundedPayloadTransferLimits {
    public record Budget(long maxTotalBytes, int maxChunks) { }
    private BoundedPayloadTransferLimits() { }

    public static Budget budget(BoundedPayloadKind kind) throws BoundedPayloadException {
        return switch (kind) {
            case BOUNDED_PAYLOAD_AUTH_REQUEST -> new Budget(
                    ProtocolConstants.MAX_AUTH_REQUEST_TRANSFER_BYTES,
                    ProtocolConstants.MAX_AUTH_REQUEST_TRANSFER_CHUNKS);
            case BOUNDED_PAYLOAD_ARTIFACT_OBSERVATION -> new Budget(
                    ProtocolConstants.MAX_ARTIFACT_OBSERVATION_TRANSFER_BYTES,
                    ProtocolConstants.MAX_ARTIFACT_OBSERVATION_TRANSFER_CHUNKS);
            case BOUNDED_PAYLOAD_KIND_UNSPECIFIED, UNRECOGNIZED ->
                    throw new BoundedPayloadException("unsupported bounded payload kind");
        };
    }

    public static void validateFrameBytes(int bytes) throws BoundedPayloadException {
        if (bytes <= 0 || bytes > ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES) {
            throw new BoundedPayloadException("signed plugin frame exceeds 30 KiB budget");
        }
    }

    public static void validateShape(BoundedPayloadKind kind, long totalBytes, int totalChunks)
            throws BoundedPayloadException {
        Budget budget = budget(kind);
        if (totalBytes <= 0 || totalBytes > budget.maxTotalBytes() || totalChunks <= 0
                || totalChunks > budget.maxChunks()) {
            throw new BoundedPayloadException("transfer shape exceeds " + kind + " budget");
        }
        long minimum = (totalBytes + ProtocolConstants.MAX_BOUNDED_PAYLOAD_CHUNK_BYTES - 1)
                / ProtocolConstants.MAX_BOUNDED_PAYLOAD_CHUNK_BYTES;
        if (totalChunks < minimum) throw new BoundedPayloadException("transfer declares too few chunks");
    }

    public static void validateChunk(byte[] bytes, byte[] advertisedHash) throws BoundedPayloadException {
        if (bytes.length == 0 || bytes.length > ProtocolConstants.MAX_BOUNDED_PAYLOAD_CHUNK_BYTES
                || advertisedHash.length != 32 || !MessageDigest.isEqual(sha256(bytes), advertisedHash)) {
            throw new BoundedPayloadException("invalid bounded transfer chunk");
        }
    }

    public static byte[] sha256(byte[] input) throws BoundedPayloadException {
        try { return MessageDigest.getInstance("SHA-256").digest(input); }
        catch (NoSuchAlgorithmException exception) { throw new BoundedPayloadException("SHA-256 unavailable", exception); }
    }

    public static byte[] merkleRoot(List<byte[]> hashes) throws BoundedPayloadException {
        if (hashes.isEmpty()) throw new BoundedPayloadException("Merkle tree requires chunks");
        List<byte[]> level = new ArrayList<>(hashes.size());
        for (byte[] hash : hashes) {
            if (hash.length != 32) throw new BoundedPayloadException("invalid Merkle leaf");
            level.add(hash.clone());
        }
        while (level.size() > 1) {
            List<byte[]> next = new ArrayList<>((level.size() + 1) / 2);
            for (int i = 0; i < level.size(); i += 2) {
                byte[] left = level.get(i); byte[] right = level.get(Math.min(i + 1, level.size() - 1));
                byte[] joined = new byte[64];
                System.arraycopy(left, 0, joined, 0, 32); System.arraycopy(right, 0, joined, 32, 32);
                next.add(sha256(joined));
            }
            level = next;
        }
        return level.getFirst();
    }
}
