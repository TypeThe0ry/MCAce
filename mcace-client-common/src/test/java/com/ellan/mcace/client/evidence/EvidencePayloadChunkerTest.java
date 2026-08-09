package com.ellan.mcace.client.evidence;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import com.ellan.mcace.protocol.ProtocolConstants;
import org.junit.jupiter.api.Test;

final class EvidencePayloadChunkerTest {
    private final EvidencePayloadChunker chunker = new EvidencePayloadChunker();

    @Test
    void chunksAtExactBoundariesAndComputesStableHashes() {
        ChunkedEvidencePayload result = chunker.chunk(bytes("abcdef"), new EvidencePayloadChunker.Limits(3, 6, 2));

        assertEquals(6, result.totalBytes());
        assertEquals(2, result.chunks().size());
        assertArrayEquals(bytes("abc"), result.chunks().get(0).content());
        assertArrayEquals(bytes("def"), result.chunks().get(1).content());
        assertEquals("bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721", result.sha256Hex());
    }

    @Test
    void merkleRootIsDeterministicIncludingOddLeafCounts() {
        byte[] payload = bytes("abcdefg");
        EvidencePayloadChunker.Limits limits = new EvidencePayloadChunker.Limits(3, 7, 3);

        ChunkedEvidencePayload first = chunker.chunk(payload, limits);
        ChunkedEvidencePayload second = chunker.chunk(payload, limits);

        assertEquals(3, first.chunks().size());
        assertArrayEquals(first.merkleRoot(), second.merkleRoot());
        assertArrayEquals(first.sha256(), second.sha256());
    }

    @Test
    void oneByteTamperingChangesPayloadAndMerkleHashes() {
        EvidencePayloadChunker.Limits limits = new EvidencePayloadChunker.Limits(2, 4, 2);
        ChunkedEvidencePayload original = chunker.chunk(bytes("abcd"), limits);
        ChunkedEvidencePayload changed = chunker.chunk(bytes("abce"), limits);

        assertNotEquals(original.sha256Hex(), changed.sha256Hex());
        assertNotEquals(original.merkleRootHex(), changed.merkleRootHex());
        assertNotEquals(original.chunks().get(1).sha256Hex(), changed.chunks().get(1).sha256Hex());
    }

    @Test
    void acceptsMaximumValuesAndRejectsInvalidOrExceededInputs() {
        assertEquals(1, chunker.chunk(bytes("abc"), 3, 3, 1).chunks().size());
        assertThrows(IllegalArgumentException.class, () -> chunker.chunk(new byte[0], 1, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> chunker.chunk(bytes("a"), 0, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> chunker.chunk(bytes("ab"), 1, 1, 2));
        assertThrows(IllegalArgumentException.class, () -> chunker.chunk(bytes("ab"), 1, 2, 1));
        assertThrows(IllegalArgumentException.class, () -> new EvidencePayloadChunker.Limits(1, Long.MAX_VALUE, 0));
    }

    @Test
    void protocolDefaultsStayBoundToWireLimits() {
        EvidencePayloadChunker.Limits limits = EvidencePayloadChunker.Limits.protocolDefaults();
        assertEquals(ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES, limits.maxChunkBytes());
        assertEquals(ProtocolConstants.MAX_EVIDENCE_TOTAL_BYTES, limits.maxTotalBytes());
        assertEquals(ProtocolConstants.MAX_EVIDENCE_CHUNKS, limits.maxChunks());
    }

    @Test
    void defensivelyCopiesInputAndExposedArrays() {
        byte[] payload = bytes("abcd");
        ChunkedEvidencePayload result = chunker.chunk(payload, 2, 4, 2);
        String payloadHash = result.sha256Hex();
        byte[] originalRoot = result.merkleRoot();
        payload[0] = 'z';
        byte[] content = result.chunks().getFirst().content();
        content[0] = 'z';
        byte[] root = result.merkleRoot();
        root[0] = 0;

        assertEquals(payloadHash, result.sha256Hex());
        assertArrayEquals(bytes("ab"), result.chunks().getFirst().content());
        assertArrayEquals(originalRoot, result.merkleRoot());
    }

    @Test
    void clearsOwnedPayloadAndHashBuffersAfterTransferConstruction() {
        ChunkedEvidencePayload result = chunker.chunk(bytes("secret-frame"), 4, 12, 3);

        result.clear();

        assertArrayEquals(new byte[32], result.sha256());
        assertArrayEquals(new byte[32], result.merkleRoot());
        assertArrayEquals(new byte[4], result.chunks().getFirst().content());
        assertArrayEquals(new byte[32], result.chunks().getFirst().sha256());
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
