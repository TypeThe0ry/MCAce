package com.ellan.mcace.protocol.evidence;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.generated.EvidenceBegin;
import com.ellan.mcace.protocol.generated.EvidenceChunk;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import com.ellan.mcace.protocol.generated.EvidenceCommit;
import com.ellan.mcace.protocol.generated.EvidenceRequest;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.transport.BoundedPayloadException;
import com.ellan.mcace.protocol.transport.BoundedPayloadTransferLimits;
import com.google.protobuf.ByteString;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Creates request-bound, signed evidence Begin/Chunk/Commit frames. */
public final class EvidenceTransferSender {
    public List<byte[]> send(
            String sessionId,
            EvidenceRequest request,
            byte[] content,
            int widthPixels,
            int heightPixels,
            long capturedAtEpochMs,
            long startSequence,
            EnvelopeCodec codec,
            PrivateKey privateKey) throws BoundedPayloadException, EnvelopeException {
        if (sessionId == null || sessionId.isBlank()) {
            throw new BoundedPayloadException("sessionId is required");
        }
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(codec, "codec");
        Objects.requireNonNull(privateKey, "privateKey");
        if (request.getType() != com.ellan.mcace.protocol.generated.EvidenceType.SCREENSHOT
                || request.getCaptureScope()
                != com.ellan.mcace.protocol.generated.EvidenceCaptureScope.GAME_RENDER_FRAME) {
            throw new BoundedPayloadException("only game-render-frame evidence can be transferred");
        }
        if (startSequence == 0L || content.length == 0) {
            throw new BoundedPayloadException("invalid evidence transfer sequence or content");
        }
        if (content.length > ProtocolConstants.MAX_EVIDENCE_TOTAL_BYTES) {
            throw new BoundedPayloadException("evidence content exceeds total byte budget");
        }
        if (widthPixels <= 0 || heightPixels <= 0
                || (long) widthPixels * heightPixels > ProtocolConstants.MAX_EVIDENCE_PIXELS) {
            throw new BoundedPayloadException("evidence image exceeds pixel budget");
        }
        int chunks = (int) ((content.length + ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES - 1L)
                / ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES);
        if (chunks <= 0 || chunks > ProtocolConstants.MAX_EVIDENCE_CHUNKS) {
            throw new BoundedPayloadException("evidence content exceeds chunk budget");
        }
        long sequence = startSequence;
        for (int index = 0; index < chunks + 1; index++) {
            sequence = EvidenceTransferLimits.nextUnsignedSequence(sequence);
        }
        byte[] contentHash = BoundedPayloadTransferLimits.sha256(content);
        List<byte[]> pieces = new ArrayList<>(chunks);
        List<byte[]> chunkHashes = new ArrayList<>(chunks);
        for (int offset = 0; offset < content.length; offset += ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES) {
            int length = Math.min(ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES, content.length - offset);
            byte[] piece = java.util.Arrays.copyOfRange(content, offset, offset + length);
            pieces.add(piece);
            chunkHashes.add(BoundedPayloadTransferLimits.sha256(piece));
        }
        byte[] merkleRoot = BoundedPayloadTransferLimits.merkleRoot(chunkHashes);
        EvidenceBegin begin = EvidenceBegin.newBuilder()
                .setEvidenceId(request.getEvidenceId())
                .setType(request.getType())
                .setCaptureScope(request.getCaptureScope())
                .setCollectionStatus(EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED)
                .setCapturedAtEpochMs(capturedAtEpochMs)
                .setTotalBytes(content.length)
                .setTotalChunks(chunks)
                .setWidthPixels(widthPixels)
                .setHeightPixels(heightPixels)
                .setContentSha256(ByteString.copyFrom(contentHash))
                .setMerkleRootSha256(ByteString.copyFrom(merkleRoot))
                .setRequestId(request.getRequestId())
                .setPlayerId(request.getPlayerId())
                .setTransportSequence(startSequence)
                .build();
        EvidenceTransferLimits.validateBegin(begin);
        List<byte[]> frames = new ArrayList<>(chunks + 2);
        sequence = startSequence;
        frames.add(frame(codec.sign(PacketType.EVIDENCE_BEGIN, sessionId, begin.toByteArray(), privateKey)));
        for (int index = 0; index < pieces.size(); index++) {
            sequence = EvidenceTransferLimits.nextUnsignedSequence(sequence);
            EvidenceChunk chunk = EvidenceChunk.newBuilder()
                    .setEvidenceId(request.getEvidenceId())
                    .setChunkIndex(index)
                    .setContent(ByteString.copyFrom(pieces.get(index)))
                    .setChunkSha256(ByteString.copyFrom(chunkHashes.get(index)))
                    .setRequestId(request.getRequestId())
                    .setPlayerId(request.getPlayerId())
                    .setTransportSequence(sequence)
                    .build();
            frames.add(frame(codec.sign(PacketType.EVIDENCE_CHUNK, sessionId, chunk.toByteArray(), privateKey)));
        }
        sequence = EvidenceTransferLimits.nextUnsignedSequence(sequence);
        EvidenceCommit commit = EvidenceCommit.newBuilder()
                .setEvidenceId(request.getEvidenceId())
                .setTotalBytes(content.length)
                .setTotalChunks(chunks)
                .setContentSha256(ByteString.copyFrom(contentHash))
                .setMerkleRootSha256(ByteString.copyFrom(merkleRoot))
                .setCollectionStatus(EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED)
                .setRequestId(request.getRequestId())
                .setPlayerId(request.getPlayerId())
                .setTransportSequence(sequence)
                .build();
        frames.add(frame(codec.sign(PacketType.EVIDENCE_COMMIT, sessionId, commit.toByteArray(), privateKey)));
        return List.copyOf(frames);
    }

    private static byte[] frame(SignedEnvelope envelope) throws BoundedPayloadException {
        byte[] encoded = envelope.toByteArray();
        BoundedPayloadTransferLimits.validateFrameBytes(encoded.length);
        return encoded;
    }
}
