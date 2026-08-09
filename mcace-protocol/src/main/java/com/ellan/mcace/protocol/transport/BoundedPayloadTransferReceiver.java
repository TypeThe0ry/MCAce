package com.ellan.mcace.protocol.transport;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.AuthRequest;
import com.ellan.mcace.protocol.generated.ArtifactObservationUpdate;
import com.ellan.mcace.protocol.generated.BoundedPayloadBegin;
import com.ellan.mcace.protocol.generated.BoundedPayloadChunk;
import com.ellan.mcace.protocol.generated.BoundedPayloadCommit;
import com.ellan.mcace.protocol.generated.BoundedPayloadKind;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * One authenticated session's strictly ordered, single-in-flight bounded payload receiver.
 * Signature, nonce replay, and header session binding are verified by {@link #accept}; adapters
 * which have already done that may call {@link #acceptVerified(SignedEnvelope)} instead.
 */
public final class BoundedPayloadTransferReceiver {
    public record CompletedPayload(BoundedPayloadKind kind, byte[] manifestRootSha256, byte[] content) {
        public CompletedPayload { manifestRootSha256 = manifestRootSha256.clone(); content = content.clone(); }
        @Override public byte[] manifestRootSha256() { return manifestRootSha256.clone(); }
        @Override public byte[] content() { return content.clone(); }
    }

    private final String sessionId;
    private final Clock clock;
    private final long ttlMillis;
    private Active active;

    public BoundedPayloadTransferReceiver(String sessionId, Clock clock, Duration ttl) {
        this.sessionId = Objects.requireNonNull(sessionId, "sessionId");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (sessionId.isBlank() || Objects.requireNonNull(ttl, "ttl").isNegative() || ttl.isZero()) {
            throw new IllegalArgumentException("sessionId and positive ttl are required");
        }
        ttlMillis = ttl.toMillis();
    }

    public BoundedPayloadTransferReceiver(String sessionId) {
        this(sessionId, Clock.systemUTC(), ProtocolConstants.DEFAULT_BOUNDED_PAYLOAD_TTL);
    }

    /** Bounded raw-frame entry point: checks the common 30KiB limit before protobuf parsing. */
    public synchronized Optional<CompletedPayload> accept(
            byte[] encodedFrame, EnvelopeCodec codec, PublicKey publicKey, NonceReplayGuard replayGuard)
            throws BoundedPayloadException, EnvelopeException {
        Objects.requireNonNull(encodedFrame, "encodedFrame");
        BoundedPayloadTransferLimits.validateFrameBytes(encodedFrame.length);
        SignedEnvelope envelope = Objects.requireNonNull(codec, "codec").parse(encodedFrame);
        codec.verify(envelope, Objects.requireNonNull(publicKey, "publicKey"),
                Objects.requireNonNull(replayGuard, "replayGuard"));
        return acceptVerified(envelope);
    }

    /** Call only after the envelope's signature and nonce have been verified by EnvelopeCodec. */
    public synchronized Optional<CompletedPayload> acceptVerified(SignedEnvelope envelope)
            throws BoundedPayloadException {
        Objects.requireNonNull(envelope, "envelope");
        if (!envelope.hasHeader() || !sessionId.equals(envelope.getHeader().getSessionId())) {
            throw new BoundedPayloadException("bounded payload envelope session mismatch");
        }
        expireIfNeeded();
        try {
            return switch (envelope.getHeader().getPacketType()) {
                case PAYLOAD_BEGIN -> {
                    BoundedPayloadBegin parsed = BoundedPayloadBegin.parseFrom(envelope.getPayload());
                    rejectUnknownFields(parsed);
                    begin(parsed);
                    yield Optional.empty();
                }
                case PAYLOAD_CHUNK -> {
                    BoundedPayloadChunk parsed = BoundedPayloadChunk.parseFrom(envelope.getPayload());
                    rejectUnknownFields(parsed);
                    chunk(parsed);
                    yield Optional.empty();
                }
                case PAYLOAD_COMMIT -> {
                    BoundedPayloadCommit parsed = BoundedPayloadCommit.parseFrom(envelope.getPayload());
                    rejectUnknownFields(parsed);
                    yield Optional.of(commit(parsed));
                }
                default -> throw new BoundedPayloadException("unexpected packet type for bounded payload");
            };
        } catch (InvalidProtocolBufferException exception) {
            // A truncated or otherwise malformed fragment must not pin the single in-flight
            // slot until TTL. Keep the malformed-message path equivalent to semantic failures.
            active = null;
            throw new BoundedPayloadException("malformed bounded payload message", exception);
        } catch (BoundedPayloadException exception) {
            // A malformed, conflicting, or out-of-order fragment must not reserve the sole
            // in-flight slot until TTL. The nonce is still consumed by EnvelopeCodec.
            active = null;
            throw exception;
        }
    }

    private void begin(BoundedPayloadBegin begin) throws BoundedPayloadException {
        if (active != null) throw new BoundedPayloadException("a payload transfer is already active");
        requireId(begin.getTransferId());
        requireHash(begin.getManifestRootSha256().toByteArray(), "manifest root");
        requireHash(begin.getContentSha256().toByteArray(), "content hash");
        requireHash(begin.getMerkleRootSha256().toByteArray(), "Merkle root");
        if (begin.getTransportSequence() <= 0) throw new BoundedPayloadException("transfer sequence must be positive");
        BoundedPayloadTransferLimits.validateShape(begin.getPayloadKind(), begin.getTotalBytes(), begin.getTotalChunks());
        if (begin.getTransportSequence() > Long.MAX_VALUE - begin.getTotalChunks() - 1L) {
            throw new BoundedPayloadException("transfer sequence would overflow");
        }
        active = new Active(begin, clock.millis(), begin.getTransportSequence() + 1L);
    }

    private void chunk(BoundedPayloadChunk chunk) throws BoundedPayloadException {
        Active current = requireActive(chunk.getTransferId(), chunk.getPayloadKind(), chunk.getTransportSequence());
        if (chunk.getChunkIndex() != current.chunks.size() || chunk.getChunkIndex() >= current.begin.getTotalChunks()) {
            throw new BoundedPayloadException("out-of-order or conflicting chunk index");
        }
        byte[] content = chunk.getContent().toByteArray();
        BoundedPayloadTransferLimits.validateChunk(content, chunk.getChunkSha256().toByteArray());
        if (content.length > current.begin.getTotalBytes() - current.bytes) {
            throw new BoundedPayloadException("chunk exceeds declared total bytes");
        }
        current.chunks.add(content);
        current.chunkHashes.add(chunk.getChunkSha256().toByteArray());
        current.bytes += content.length;
        current.nextSequence++;
    }

    private CompletedPayload commit(BoundedPayloadCommit commit) throws BoundedPayloadException {
        Active current = requireActive(commit.getTransferId(), commit.getPayloadKind(), commit.getTransportSequence());
        if (commit.getTotalBytes() != current.begin.getTotalBytes() || commit.getTotalChunks() != current.begin.getTotalChunks()
                || current.bytes != current.begin.getTotalBytes() || current.chunks.size() != current.begin.getTotalChunks()
                || !MessageDigest.isEqual(commit.getContentSha256().toByteArray(), current.begin.getContentSha256().toByteArray())
                || !MessageDigest.isEqual(commit.getMerkleRootSha256().toByteArray(), current.begin.getMerkleRootSha256().toByteArray())) {
            throw new BoundedPayloadException("bounded payload commit conflicts with begin or chunks");
        }
        byte[] content = join(current.chunks, (int) current.bytes);
        if (!MessageDigest.isEqual(BoundedPayloadTransferLimits.sha256(content), current.begin.getContentSha256().toByteArray())
                || !MessageDigest.isEqual(BoundedPayloadTransferLimits.merkleRoot(current.chunkHashes), current.begin.getMerkleRootSha256().toByteArray())) {
            throw new BoundedPayloadException("bounded payload content integrity mismatch");
        }
        if (current.begin.getPayloadKind() == BoundedPayloadKind.BOUNDED_PAYLOAD_AUTH_REQUEST) {
            try {
                if (!MessageDigest.isEqual(AuthRequest.parseFrom(content).getManifestRootSha256().toByteArray(),
                        current.begin.getManifestRootSha256().toByteArray())) {
                    throw new BoundedPayloadException("auth request manifest root is not bound to transfer begin");
                }
            } catch (InvalidProtocolBufferException exception) {
                throw new BoundedPayloadException("fragmented auth request is malformed", exception);
            }
        } else if (current.begin.getPayloadKind()
                == BoundedPayloadKind.BOUNDED_PAYLOAD_ARTIFACT_OBSERVATION) {
            try {
                if (!MessageDigest.isEqual(
                        ArtifactObservationUpdate.parseFrom(content).getAggregateRootSha256().toByteArray(),
                        current.begin.getManifestRootSha256().toByteArray())) {
                    throw new BoundedPayloadException(
                            "artifact observation aggregate root is not bound to transfer begin");
                }
            } catch (InvalidProtocolBufferException exception) {
                throw new BoundedPayloadException("fragmented artifact observation is malformed", exception);
            }
        }
        active = null;
        return new CompletedPayload(current.begin.getPayloadKind(), current.begin.getManifestRootSha256().toByteArray(), content);
    }

    private Active requireActive(String transferId, BoundedPayloadKind kind, long sequence) throws BoundedPayloadException {
        expireIfNeeded();
        if (active == null || !active.begin.getTransferId().equals(transferId) || active.begin.getPayloadKind() != kind
                || active.nextSequence != sequence) throw new BoundedPayloadException("out-of-order, replayed, or conflicting transfer fragment");
        return active;
    }

    private void expireIfNeeded() throws BoundedPayloadException {
        if (active != null && clock.millis() - active.startedAt > ttlMillis) {
            active = null;
            throw new BoundedPayloadException("bounded payload transfer expired");
        }
    }

    private static void requireId(String value) throws BoundedPayloadException {
        if (value == null || value.isBlank() || value.length() > 128) throw new BoundedPayloadException("invalid transfer id");
    }
    private static void rejectUnknownFields(com.google.protobuf.Message message) throws BoundedPayloadException {
        if (!message.getUnknownFields().asMap().isEmpty()) {
            throw new BoundedPayloadException("unknown bounded payload fields");
        }
    }
    private static void requireHash(byte[] value, String name) throws BoundedPayloadException {
        if (value.length != 32) throw new BoundedPayloadException(name + " must be SHA-256");
    }
    private static byte[] join(List<byte[]> chunks, int length) {
        ByteArrayOutputStream output = new ByteArrayOutputStream(length);
        for (byte[] chunk : chunks) output.writeBytes(chunk);
        return output.toByteArray();
    }
    private static final class Active {
        private final BoundedPayloadBegin begin; private final long startedAt;
        private long nextSequence; private long bytes;
        private final List<byte[]> chunks = new ArrayList<>(); private final List<byte[]> chunkHashes = new ArrayList<>();
        private Active(BoundedPayloadBegin begin, long startedAt, long nextSequence) {
            this.begin = begin; this.startedAt = startedAt; this.nextSequence = nextSequence;
        }
    }
}
