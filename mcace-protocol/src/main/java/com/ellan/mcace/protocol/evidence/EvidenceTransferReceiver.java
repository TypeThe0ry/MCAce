package com.ellan.mcace.protocol.evidence;

import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.EvidenceBegin;
import com.ellan.mcace.protocol.generated.EvidenceChunk;
import com.ellan.mcace.protocol.generated.EvidenceCommit;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceRequest;
import com.ellan.mcace.protocol.generated.EvidenceType;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.transport.BoundedPayloadException;
import com.ellan.mcace.protocol.transport.BoundedPayloadTransferLimits;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Receives one request-bound evidence transfer without publishing partial content. */
public final class EvidenceTransferReceiver {
    public record CompletedEvidence(
            String requestId,
            String playerId,
            String evidenceId,
            EvidenceType type,
            EvidenceCaptureScope captureScope,
            EvidenceCollectionStatus collectionStatus,
            long capturedAtEpochMs,
            int widthPixels,
            int heightPixels,
            byte[] contentSha256,
            byte[] merkleRootSha256,
            byte[] content) {
        public CompletedEvidence {
            contentSha256 = contentSha256.clone();
            merkleRootSha256 = merkleRootSha256.clone();
            content = content.clone();
        }

        @Override public byte[] contentSha256() { return contentSha256.clone(); }
        @Override public byte[] merkleRootSha256() { return merkleRootSha256.clone(); }
        @Override public byte[] content() { return content.clone(); }
    }

    private final EvidenceRequest request;
    private final String sessionId;
    private final Clock clock;
    private long lastObservedAtEpochMs;
    private Active active;

    public EvidenceTransferReceiver(String sessionId, EvidenceRequest request, Clock clock) {
        this.sessionId = requireIdentifier(sessionId, "sessionId");
        this.request = Objects.requireNonNull(request, "request");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.lastObservedAtEpochMs = clock.millis();
        EvidenceTransferLimits.validateRequest(request, lastObservedAtEpochMs);
    }

    /** Raw-frame size is checked before protobuf parsing or allocation of transfer state. */
    public synchronized Optional<CompletedEvidence> accept(
            byte[] encodedFrame,
            EnvelopeCodec codec,
            PublicKey publicKey,
            NonceReplayGuard replayGuard) throws BoundedPayloadException, EnvelopeException {
        Objects.requireNonNull(encodedFrame, "encodedFrame");
        BoundedPayloadTransferLimits.validateFrameBytes(encodedFrame.length);
        SignedEnvelope envelope = Objects.requireNonNull(codec, "codec").parse(encodedFrame);
        codec.verify(envelope, Objects.requireNonNull(publicKey, "publicKey"),
                Objects.requireNonNull(replayGuard, "replayGuard"));
        return acceptVerified(envelope);
    }

    public synchronized Optional<CompletedEvidence> acceptVerified(SignedEnvelope envelope)
            throws BoundedPayloadException {
        Objects.requireNonNull(envelope, "envelope");
        if (!envelope.hasHeader() || !sessionId.equals(envelope.getHeader().getSessionId())) {
            throw new BoundedPayloadException("evidence envelope session mismatch");
        }
        expireIfNeeded();
        try {
            return switch (envelope.getHeader().getPacketType()) {
                case EVIDENCE_BEGIN -> {
                    EvidenceBegin parsed = EvidenceBegin.parseFrom(envelope.getPayload());
                    rejectUnknownFields(parsed);
                    begin(parsed);
                    yield Optional.empty();
                }
                case EVIDENCE_CHUNK -> {
                    EvidenceChunk parsed = EvidenceChunk.parseFrom(envelope.getPayload());
                    rejectUnknownFields(parsed);
                    chunk(parsed);
                    yield Optional.empty();
                }
                case EVIDENCE_COMMIT -> {
                    EvidenceCommit parsed = EvidenceCommit.parseFrom(envelope.getPayload());
                    rejectUnknownFields(parsed);
                    yield Optional.of(commit(parsed));
                }
                default -> throw new BoundedPayloadException("unexpected packet type for evidence transfer");
            };
        } catch (InvalidProtocolBufferException exception) {
            active = null;
            throw new BoundedPayloadException("malformed evidence transfer message", exception);
        } catch (BoundedPayloadException | IllegalArgumentException exception) {
            active = null;
            if (exception instanceof BoundedPayloadException bounded) {
                throw bounded;
            }
            throw new BoundedPayloadException("invalid evidence transfer", exception);
        }
    }

    private void begin(EvidenceBegin begin) {
        if (active != null) {
            throw new IllegalArgumentException("an evidence transfer is already active");
        }
        EvidenceTransferLimits.validateBegin(begin, observedNow());
        requireBinding(begin.getRequestId(), begin.getPlayerId(), begin.getEvidenceId());
        if (begin.getType() != request.getType() || begin.getCaptureScope() != request.getCaptureScope()) {
            throw new IllegalArgumentException("evidence transfer scope is not bound to request");
        }
        if (begin.getCollectionStatus() != EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED) {
            throw new IllegalArgumentException("non-collected evidence cannot start a transfer");
        }
        active = new Active(begin, begin.getTransportSequence());
    }

    private void chunk(EvidenceChunk chunk) {
        Active current = requireActive();
        EvidenceTransferLimits.validateChunk(chunk, current.begin);
        requireIncreasingSequence(chunk.getTransportSequence(), current.lastSequence);
        if (chunk.getChunkIndex() != current.chunks.size()
                || chunk.getChunkIndex() >= current.begin.getTotalChunks()) {
            throw new IllegalArgumentException("evidence chunks are out of order");
        }
        byte[] content = chunk.getContent().toByteArray();
        if (current.bytes > current.begin.getTotalBytes() - content.length) {
            throw new IllegalArgumentException("evidence chunks exceed declared total bytes");
        }
        current.chunks.add(content);
        current.chunkHashes.add(chunk.getChunkSha256().toByteArray());
        current.bytes += content.length;
        current.lastSequence = chunk.getTransportSequence();
    }

    private CompletedEvidence commit(EvidenceCommit commit) throws BoundedPayloadException {
        Active current = requireActive();
        EvidenceTransferLimits.validateCommit(commit, current.begin);
        requireIncreasingSequence(commit.getTransportSequence(), current.lastSequence);
        if (current.bytes != current.begin.getTotalBytes()
                || current.chunks.size() != current.begin.getTotalChunks()) {
            throw new IllegalArgumentException("evidence commit is incomplete");
        }
        byte[] content = join(current.chunks, (int) current.bytes);
        if (!MessageDigest.isEqual(BoundedPayloadTransferLimits.sha256(content),
                current.begin.getContentSha256().toByteArray())
                || !MessageDigest.isEqual(BoundedPayloadTransferLimits.merkleRoot(current.chunkHashes),
                current.begin.getMerkleRootSha256().toByteArray())) {
            throw new IllegalArgumentException("evidence content hash or Merkle root mismatch");
        }
        active = null;
        return new CompletedEvidence(
                request.getRequestId(), request.getPlayerId(), request.getEvidenceId(),
                current.begin.getType(), current.begin.getCaptureScope(), current.begin.getCollectionStatus(),
                current.begin.getCapturedAtEpochMs(), current.begin.getWidthPixels(), current.begin.getHeightPixels(),
                current.begin.getContentSha256().toByteArray(),
                current.begin.getMerkleRootSha256().toByteArray(), content);
    }

    private Active requireActive() {
        expireIfNeeded();
        if (active == null) {
            throw new IllegalArgumentException("no active evidence transfer");
        }
        return active;
    }

    private void expireIfNeeded() {
        if (observedNow() >= request.getExpiresAtEpochMs()) {
            active = null;
            throw new IllegalArgumentException("evidence request expired");
        }
    }

    private long observedNow() {
        long now = clock.millis();
        if (now > lastObservedAtEpochMs) {
            lastObservedAtEpochMs = now;
        }
        return lastObservedAtEpochMs;
    }

    private void requireBinding(String requestId, String playerId, String evidenceId) {
        if (!request.getRequestId().equals(requestId) || !request.getPlayerId().equals(playerId)
                || !request.getEvidenceId().equals(evidenceId)) {
            throw new IllegalArgumentException("evidence transfer is not bound to request");
        }
    }

    private static void requireIncreasingSequence(long sequence, long previous) {
        if (!EvidenceTransferLimits.isStrictlyIncreasingUnsigned(previous, sequence)) {
            throw new IllegalArgumentException("evidence transport sequence must increase");
        }
    }

    private static String requireIdentifier(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 128) {
            throw new IllegalArgumentException(name + " is required");
        }
        return value;
    }

    private static void rejectUnknownFields(com.google.protobuf.Message message) {
        if (!message.getUnknownFields().asMap().isEmpty()) {
            throw new IllegalArgumentException("unknown evidence transfer fields");
        }
    }

    private static byte[] join(List<byte[]> chunks, int length) {
        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, result, offset, chunk.length);
            offset += chunk.length;
        }
        return result;
    }

    private static final class Active {
        private final EvidenceBegin begin;
        private final List<byte[]> chunks = new ArrayList<>();
        private final List<byte[]> chunkHashes = new ArrayList<>();
        private long bytes;
        private long lastSequence;

        private Active(EvidenceBegin begin, long lastSequence) {
            this.begin = begin;
            this.lastSequence = lastSequence;
        }
    }
}
