package com.ellan.mcace.protocol.transport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.heartbeat.HeartbeatSessionStateMachine;
import com.ellan.mcace.protocol.generated.AuthRequest;
import com.ellan.mcace.protocol.generated.ArtifactObservationUpdate;
import com.ellan.mcace.protocol.generated.BoundedPayloadBegin;
import com.ellan.mcace.protocol.generated.BoundedPayloadChunk;
import com.ellan.mcace.protocol.generated.BoundedPayloadCommit;
import com.ellan.mcace.protocol.generated.BoundedPayloadKind;
import com.ellan.mcace.protocol.generated.EnvelopeHeader;
import com.ellan.mcace.protocol.generated.Heartbeat;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

final class BoundedPayloadTransferReceiverTest {
    @Test void acceptsStrictlyOrderedBoundAuthRequestAndRejectsReplay() throws Exception {
        MutableClock clock = new MutableClock(1_800_000_000_000L);
        byte[] root = new byte[32]; root[0] = 4;
        byte[] content = AuthRequest.newBuilder().setManifestRootSha256(ByteString.copyFrom(root)).build().toByteArray();
        byte[] hash = BoundedPayloadTransferLimits.sha256(content);
        BoundedPayloadTransferReceiver receiver = new BoundedPayloadTransferReceiver("session", clock, Duration.ofMinutes(1));
        receiver.acceptVerified(envelope(PacketType.PAYLOAD_BEGIN, begin(root, content.length, hash, hash, 9), "session"));
        receiver.acceptVerified(envelope(PacketType.PAYLOAD_CHUNK, chunk(content, hash, 10, 0), "session"));
        var completed = receiver.acceptVerified(envelope(PacketType.PAYLOAD_COMMIT, commit(content.length, hash, hash, 11), "session")).orElseThrow();
        assertEquals(BoundedPayloadKind.BOUNDED_PAYLOAD_AUTH_REQUEST, completed.kind());
        assertArrayEquals(content, completed.content());

        KeyPair keyPair = Ed25519Keys.generate(new SecureRandom());
        EnvelopeCodec codec = new EnvelopeCodec(clock, new SecureRandom(), ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES, Duration.ofSeconds(30));
        SignedEnvelope signed = codec.sign(PacketType.PAYLOAD_BEGIN, "session", begin(root, content.length, hash, hash, 1).toByteArray(), keyPair.getPrivate());
        BoundedPayloadTransferReceiver replayReceiver = new BoundedPayloadTransferReceiver("session", clock, Duration.ofMinutes(1));
        NonceReplayGuard guard = new NonceReplayGuard(clock, Duration.ofMinutes(5));
        replayReceiver.accept(signed.toByteArray(), codec, keyPair.getPublic(), guard);
        assertThrows(EnvelopeException.class, () -> replayReceiver.accept(signed.toByteArray(), codec, keyPair.getPublic(), guard));
    }

    @Test void rejectsOutOfOrderConflictExpiredAndOversizedFrames() throws Exception {
        MutableClock clock = new MutableClock(1_800_000_000_000L); byte[] root = new byte[32]; byte[] content = {1}; byte[] hash = BoundedPayloadTransferLimits.sha256(content);
        BoundedPayloadTransferReceiver receiver = new BoundedPayloadTransferReceiver("s", clock, Duration.ofMillis(5));
        receiver.acceptVerified(envelope(PacketType.PAYLOAD_BEGIN, begin(root, 1, hash, hash, 5), "s"));
        assertThrows(BoundedPayloadException.class, () -> receiver.acceptVerified(envelope(PacketType.PAYLOAD_CHUNK, chunk(content, hash, 7, 0), "s")));
        clock.advance(6);
        assertThrows(BoundedPayloadException.class, () -> receiver.acceptVerified(envelope(PacketType.PAYLOAD_CHUNK, chunk(content, hash, 6, 0), "s")));
        assertThrows(BoundedPayloadException.class, () -> BoundedPayloadTransferLimits.validateFrameBytes(ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES + 1));
    }

    @Test void senderCreatesProxySafeMultiChunkFramesAndTamperReleasesSlot() throws Exception {
        MutableClock clock = new MutableClock(1_800_000_000_000L); KeyPair keys = Ed25519Keys.generate(new SecureRandom());
        EnvelopeCodec codec = new EnvelopeCodec(clock, new SecureRandom(), ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES, Duration.ofSeconds(30));
        byte[] root = new byte[32]; root[0] = 7;
        byte[] content = ArtifactObservationUpdate.newBuilder()
                .setAggregateRootSha256(ByteString.copyFrom(root))
                .setPolicySha256(ByteString.copyFrom(new byte[ProtocolConstants.MAX_BOUNDED_PAYLOAD_CHUNK_BYTES + 1]))
                .build().toByteArray();
        List<byte[]> frames = new BoundedPayloadTransferSender().send(BoundedPayloadKind.BOUNDED_PAYLOAD_ARTIFACT_OBSERVATION,
                "session", content, root, 1, codec, keys.getPrivate());
        assertEquals(4, frames.size());
        BoundedPayloadTransferReceiver receiver = new BoundedPayloadTransferReceiver("session", clock, Duration.ofMinutes(1));
        NonceReplayGuard guard = new NonceReplayGuard(clock, Duration.ofMinutes(5));
        BoundedPayloadTransferReceiver.CompletedPayload complete = null;
        for (byte[] frame : frames) complete = receiver.accept(frame, codec, keys.getPublic(), guard).orElse(complete);
        assertArrayEquals(content, complete.content());
        assertThrows(BoundedPayloadException.class, () -> new BoundedPayloadTransferSender().send(
                BoundedPayloadKind.BOUNDED_PAYLOAD_ARTIFACT_OBSERVATION, "session", content, root, -1, codec, keys.getPrivate()));
        BoundedPayloadTransferReceiver reset = new BoundedPayloadTransferReceiver("s", clock, Duration.ofMinutes(1));
        byte[] one = {1}; byte[] hash = BoundedPayloadTransferLimits.sha256(one);
        reset.acceptVerified(envelope(PacketType.PAYLOAD_BEGIN, begin(root, 1, hash, hash, 1), "s"));
        assertThrows(BoundedPayloadException.class, () -> reset.acceptVerified(envelope(PacketType.PAYLOAD_CHUNK, chunk(one, new byte[32], 2, 0), "s")));
        reset.acceptVerified(envelope(PacketType.PAYLOAD_BEGIN, begin(root, 1, hash, hash, 10), "s"));
    }

    @Test
    void rejectsArtifactObservationWhoseDeclaredAggregateRootDiffersFromTransferBinding() throws Exception {
        MutableClock clock = new MutableClock(1_800_000_000_000L);
        KeyPair keys = Ed25519Keys.generate(new SecureRandom());
        EnvelopeCodec codec = new EnvelopeCodec(clock, new SecureRandom(), ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES, Duration.ofSeconds(30));
        byte[] beginRoot = new byte[32]; beginRoot[0] = 1;
        byte[] declaredRoot = new byte[32]; declaredRoot[0] = 2;
        byte[] content = ArtifactObservationUpdate.newBuilder()
                .setAggregateRootSha256(ByteString.copyFrom(declaredRoot)).build().toByteArray();
        List<byte[]> frames = new BoundedPayloadTransferSender().send(
                BoundedPayloadKind.BOUNDED_PAYLOAD_ARTIFACT_OBSERVATION, "session", content, beginRoot, 1,
                codec, keys.getPrivate());
        BoundedPayloadTransferReceiver receiver = new BoundedPayloadTransferReceiver("session", clock, Duration.ofMinutes(1));
        NonceReplayGuard guard = new NonceReplayGuard(clock, Duration.ofMinutes(5));
        receiver.accept(frames.getFirst(), codec, keys.getPublic(), guard);
        for (int index = 1; index < frames.size() - 1; index++) {
            receiver.accept(frames.get(index), codec, keys.getPublic(), guard);
        }
        assertThrows(BoundedPayloadException.class,
                () -> receiver.accept(frames.getLast(), codec, keys.getPublic(), guard));
    }

    @Test
    void maximumAuthTransferLeavesCapacityForHeartbeatOnSameSession() throws Exception {
        MutableClock clock = new MutableClock(1_800_000_000_000L);
        KeyPair keys = Ed25519Keys.generate(new SecureRandom());
        EnvelopeCodec codec = new EnvelopeCodec(clock, new SecureRandom(),
                ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES, Duration.ofSeconds(30));
        byte[] root = new byte[32];
        byte[] baseAuthRequest = AuthRequest.newBuilder()
                .setManifestRootSha256(ByteString.copyFrom(root))
                .build()
                .toByteArray();
        int targetBytes = (int) ProtocolConstants.MAX_AUTH_REQUEST_TRANSFER_BYTES;
        ByteString unknownField = ByteString.copyFrom(
                new byte[targetBytes - baseAuthRequest.length - 5]);
        assertEquals(targetBytes,
                baseAuthRequest.length + CodedOutputStream.computeBytesSize(1000, unknownField));
        ByteArrayOutputStream contentOutput = new ByteArrayOutputStream(targetBytes);
        CodedOutputStream coded = CodedOutputStream.newInstance(contentOutput);
        coded.writeRawBytes(baseAuthRequest);
        coded.writeBytes(1000, unknownField);
        coded.flush();
        byte[] content = contentOutput.toByteArray();
        List<byte[]> frames = new BoundedPayloadTransferSender().send(
                BoundedPayloadKind.BOUNDED_PAYLOAD_AUTH_REQUEST, "session", content, root, 1,
                codec, keys.getPrivate());
        assertEquals(ProtocolConstants.MAX_AUTH_REQUEST_TRANSFER_CHUNKS + 2, frames.size());

        NonceReplayGuard guard = new NonceReplayGuard(clock, ProtocolConstants.DEFAULT_REPLAY_WINDOW);
        BoundedPayloadTransferReceiver receiver = new BoundedPayloadTransferReceiver(
                "session", clock, Duration.ofMinutes(1));
        BoundedPayloadTransferReceiver.CompletedPayload completed = null;
        for (byte[] frame : frames) {
            completed = receiver.accept(frame, codec, keys.getPublic(), guard).orElse(completed);
        }
        assertNotNull(completed);
        assertArrayEquals(root, completed.manifestRootSha256());
        assertArrayEquals(content, completed.content());

        Heartbeat heartbeat = Heartbeat.newBuilder().setSequence(1).setCurrentServer("server")
                .setClientStatus(TrustLevel.VERIFIED).setManifestRootSha256(ByteString.copyFrom(root))
                .setPolicySequence(1).setPolicySha256(ByteString.copyFrom(root))
                .setAggregateRootSha256(ByteString.copyFrom(root)).build();
        HeartbeatSessionStateMachine state = new HeartbeatSessionStateMachine(
                "session", root, 1, root, root, clock);
        state.accept(codec.sign(PacketType.HEARTBEAT, "session", heartbeat.toByteArray(), keys.getPrivate())
                .toByteArray(), codec, keys.getPublic(), guard);
    }

    private static BoundedPayloadBegin begin(byte[] root, int bytes, byte[] contentHash, byte[] merkle, long sequence) {
        return BoundedPayloadBegin.newBuilder().setTransferId("transfer").setPayloadKind(BoundedPayloadKind.BOUNDED_PAYLOAD_AUTH_REQUEST)
                .setTransportSequence(sequence).setManifestRootSha256(ByteString.copyFrom(root)).setTotalBytes(bytes).setTotalChunks(1)
                .setContentSha256(ByteString.copyFrom(contentHash)).setMerkleRootSha256(ByteString.copyFrom(merkle)).build();
    }
    private static BoundedPayloadChunk chunk(byte[] content, byte[] hash, long sequence, int index) {
        return BoundedPayloadChunk.newBuilder().setTransferId("transfer").setPayloadKind(BoundedPayloadKind.BOUNDED_PAYLOAD_AUTH_REQUEST)
                .setTransportSequence(sequence).setChunkIndex(index).setContent(ByteString.copyFrom(content)).setChunkSha256(ByteString.copyFrom(hash)).build();
    }
    private static BoundedPayloadCommit commit(int bytes, byte[] contentHash, byte[] merkle, long sequence) {
        return BoundedPayloadCommit.newBuilder().setTransferId("transfer").setPayloadKind(BoundedPayloadKind.BOUNDED_PAYLOAD_AUTH_REQUEST)
                .setTransportSequence(sequence).setTotalBytes(bytes).setTotalChunks(1).setContentSha256(ByteString.copyFrom(contentHash)).setMerkleRootSha256(ByteString.copyFrom(merkle)).build();
    }
    private static SignedEnvelope envelope(PacketType type, com.google.protobuf.Message payload, String session) {
        return SignedEnvelope.newBuilder().setHeader(EnvelopeHeader.newBuilder().setProtocolVersion(1).setPacketType(type).setSessionId(session))
                .setPayload(ByteString.copyFrom(payload.toByteArray())).build();
    }
    private static final class MutableClock extends Clock {
        private final AtomicLong now; MutableClock(long now) { this.now = new AtomicLong(now); }
        void advance(long millis) { now.addAndGet(millis); }
        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return Instant.ofEpochMilli(now.get()); }
    }
}
