package com.ellan.mcace.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.protocol.evidence.EvidenceTransferLimits;
import com.ellan.mcace.protocol.evidence.EvidenceRequestVerifier;
import com.ellan.mcace.protocol.evidence.EvidenceTransferReceiver;
import com.ellan.mcace.protocol.evidence.EvidenceTransferSender;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.transport.BoundedPayloadException;
import com.ellan.mcace.protocol.generated.DetectionArtifactType;
import com.ellan.mcace.protocol.generated.DetectionConfidence;
import com.ellan.mcace.protocol.generated.DetectionMatchType;
import com.ellan.mcace.protocol.generated.DetectionRule;
import com.ellan.mcace.protocol.generated.DetectionSelector;
import com.ellan.mcace.protocol.generated.DispositionAction;
import com.ellan.mcace.protocol.generated.DispositionPolicyDocument;
import com.ellan.mcace.protocol.generated.EvidenceBegin;
import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceChunk;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import com.ellan.mcace.protocol.generated.EvidenceCommit;
import com.ellan.mcace.protocol.generated.EvidenceType;
import com.ellan.mcace.protocol.generated.EvidenceResponse;
import com.ellan.mcace.protocol.generated.EvidenceRequest;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

final class EvidenceProtocolTest {
    @Test
    void dispositionDocumentRoundTripsWithVersionAndChain() throws Exception {
        DetectionRule rule = DetectionRule.newBuilder()
                .setRuleId("xray-pack-001")
                .setPriority(500)
                .setSelector(DetectionSelector.newBuilder()
                        .setArtifactType(DetectionArtifactType.DETECTION_ARTIFACT_RESOURCE_PACK)
                        .setMatchType(DetectionMatchType.DETECTION_MATCH_EXACT_SHA256)
                        .setSha256(ByteString.copyFrom(new byte[32])))
                .setConfidence(DetectionConfidence.DETECTION_CONFIDENCE_HIGH)
                .setDefaultAction(DispositionAction.DISPOSITION_WARN)
                .setIntroducedAtEpochMs(100)
                .setExpiresAtEpochMs(200)
                .build();
        DispositionPolicyDocument original = DispositionPolicyDocument.newBuilder()
                .setSchemaVersion(1)
                .setPolicyId("network-policy")
                .setSequence(2)
                .setIssuedAtEpochMs(100)
                .setExpiresAtEpochMs(200)
                .setPreviousDocumentSha256(ByteString.copyFrom(new byte[32]))
                .addRules(rule)
                .build();

        DispositionPolicyDocument parsed = DispositionPolicyDocument.parseFrom(original.toByteArray());
        assertEquals(original, parsed);
        assertEquals(DispositionAction.DISPOSITION_WARN, parsed.getRules(0).getDefaultAction());
    }

    @Test
    void acceptsBoundedCollectedEvidenceAndRejectsLimitBypass() {
        EvidenceBegin begin = collectedBegin(ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES, 1, 1920, 1080);
        EvidenceTransferLimits.validateBegin(begin);
        EvidenceTransferLimits.validateChunk(EvidenceChunk.newBuilder()
                .setEvidenceId("e-1")
                .setChunkIndex(0)
                .setContent(ByteString.copyFrom(new byte[ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES]))
                .setChunkSha256(ByteString.copyFrom(sha256(
                        new byte[ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES])))
                .setRequestId("request-1")
                .setPlayerId(PLAYER_ID)
                .setTransportSequence(2)
                .build(), begin);
        EvidenceTransferLimits.validateCommit(EvidenceCommit.newBuilder()
                .setEvidenceId("e-1")
                .setTotalBytes(ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES)
                .setTotalChunks(1)
                .setCollectionStatus(EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED)
                .setContentSha256(begin.getContentSha256())
                .setMerkleRootSha256(begin.getMerkleRootSha256())
                .setRequestId("request-1")
                .setPlayerId(PLAYER_ID)
                .setTransportSequence(3)
                .build(), begin);

        assertThrows(IllegalArgumentException.class, () -> EvidenceTransferLimits.validateBegin(
                collectedBegin(ProtocolConstants.MAX_EVIDENCE_TOTAL_BYTES + 1, ProtocolConstants.MAX_EVIDENCE_CHUNKS, 1, 1)));
        assertThrows(IllegalArgumentException.class, () -> EvidenceTransferLimits.validateBegin(
                collectedBegin(1, 1, 2000, 2001)));
        assertThrows(IllegalArgumentException.class, () -> EvidenceTransferLimits.validateChunk(EvidenceChunk.newBuilder()
                .setEvidenceId("e-1")
                .setContent(ByteString.copyFrom(new byte[ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES + 1]))
                .setChunkSha256(ByteString.copyFrom(new byte[32]))
                .build(), begin));
        assertThrows(IllegalArgumentException.class, () -> EvidenceTransferLimits.validateChunk(
                EvidenceChunk.newBuilder()
                        .setEvidenceId("e-1")
                        .setContent(ByteString.copyFromUtf8("tampered"))
                        .setChunkSha256(ByteString.copyFrom(new byte[32]))
                        .build(), begin));
    }

    @Test
    void declinedEvidenceCannotClaimContent() {
        EvidenceBegin declined = EvidenceBegin.newBuilder()
                .setEvidenceId("e-2")
                .setType(EvidenceType.SCREENSHOT)
                .setCaptureScope(EvidenceCaptureScope.DESKTOP)
                .setCollectionStatus(EvidenceCollectionStatus.EVIDENCE_COLLECTION_DECLINED)
                .setTotalBytes(1)
                .setRequestId("request-2")
                .setPlayerId(PLAYER_ID)
                .setTransportSequence(1)
                .build();
        assertThrows(IllegalArgumentException.class, () -> EvidenceTransferLimits.validateBegin(declined));

        EvidenceBegin zeroContent = declined.toBuilder().clearTotalBytes().build();
        EvidenceTransferLimits.validateBegin(zeroContent);
        EvidenceTransferLimits.validateCommit(EvidenceCommit.newBuilder()
                .setEvidenceId(zeroContent.getEvidenceId())
                .setCollectionStatus(EvidenceCollectionStatus.EVIDENCE_COLLECTION_DECLINED)
                .setRequestId(zeroContent.getRequestId())
                .setPlayerId(zeroContent.getPlayerId())
                .setTransportSequence(2)
                .build(), zeroContent);
    }

    @Test
    void requestIsShortLivedSingleUseAndBoundToSessionAndPlayer() throws Exception {
        MutableClock clock = new MutableClock(1_800_000_000_000L);
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        EnvelopeCodec codec = new EnvelopeCodec(clock, new SecureRandom(),
                ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES, Duration.ofSeconds(30));
        EvidenceRequest request = request(clock.millis() + 60_000L, "request-1", PLAYER_ID,
                EvidenceCaptureScope.GAME_RENDER_FRAME);
        byte[] frame = codec.sign(com.ellan.mcace.protocol.generated.PacketType.EVIDENCE_REQUEST,
                "session-1", request.toByteArray(), server.getPrivate()).toByteArray();
        EvidenceRequestVerifier verifier = new EvidenceRequestVerifier(clock);
        NonceReplayGuard replay = new NonceReplayGuard(clock, Duration.ofMinutes(5));
        EvidenceRequestVerifier.VerifiedRequest verified = verifier.accept(
                frame, codec, server.getPublic(), replay, "session-1", PLAYER_ID);
        assertEquals(request, verified.request());
        assertThrows(Exception.class, () -> verifier.accept(
                codec.sign(com.ellan.mcace.protocol.generated.PacketType.EVIDENCE_REQUEST,
                        "session-1", request.toByteArray(), server.getPrivate()).toByteArray(),
                codec, server.getPublic(), replay, "session-1", PLAYER_ID));
        assertThrows(IllegalArgumentException.class, () -> EvidenceTransferLimits.validateRequest(
                request.toBuilder().addAllowedRelativePaths("mods").build(), clock.millis()));
        assertThrows(IllegalArgumentException.class, () -> EvidenceTransferLimits.validateRequest(
                request.toBuilder().setPlayerId("not-a-uuid").build(), clock.millis()));
    }

    @Test
    void retentionDisclosureDefaultsToNoRetentionAndRejectsContradictionsAndTampering() throws Exception {
        MutableClock clock = new MutableClock(1_800_000_000_000L);
        EvidenceRequest legacy = request(clock.millis() + 60_000L, "request-retention-legacy", PLAYER_ID,
                EvidenceCaptureScope.GAME_RENDER_FRAME);
        EvidenceTransferLimits.validateRequest(legacy, clock.millis());
        assertFalse(legacy.getRawContentRetained());
        assertEquals(0, legacy.getRetentionSeconds());
        assertTrue(legacy.getRetentionPolicyId().isEmpty());
        assertTrue(legacy.getRetentionPurpose().isEmpty());

        EvidenceRequest retained = legacy.toBuilder()
                .setRawContentRetained(true)
                .setRetentionSeconds(3600)
                .setRetentionPolicyId("case-review-v1")
                .setRetentionPurpose("review consented game-render evidence")
                .build();
        EvidenceTransferLimits.validateRequest(retained, clock.millis());
        assertThrows(IllegalArgumentException.class, () -> EvidenceTransferLimits.validateRequest(
                legacy.toBuilder().setRetentionSeconds(1).build(), clock.millis()));
        assertThrows(IllegalArgumentException.class, () -> EvidenceTransferLimits.validateRequest(
                retained.toBuilder().setRetentionSeconds(0).build(), clock.millis()));
        assertThrows(IllegalArgumentException.class, () -> EvidenceTransferLimits.validateRequest(
                retained.toBuilder().setRetentionPolicyId("").build(), clock.millis()));
        assertThrows(IllegalArgumentException.class, () -> EvidenceTransferLimits.validateRequest(
                retained.toBuilder().setRetentionSeconds((int) ProtocolConstants.MAX_EVIDENCE_RETENTION_SECONDS + 1)
                        .build(), clock.millis()));
        assertThrows(IllegalArgumentException.class, () -> EvidenceTransferLimits.validateRequest(
                retained.toBuilder().setRetentionPurpose("bad\npurpose").build(), clock.millis()));
        EvidenceRequest desktopRetained = retained.toBuilder()
                .setCaptureScope(EvidenceCaptureScope.DESKTOP).build();
        assertThrows(IllegalArgumentException.class, () -> EvidenceTransferLimits.validateRequest(
                desktopRetained, clock.millis()));

        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        EnvelopeCodec codec = new EnvelopeCodec(clock, new SecureRandom(),
                ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES, Duration.ofSeconds(30));
        SignedEnvelope signed = codec.sign(PacketType.EVIDENCE_REQUEST, "retention-session",
                retained.toByteArray(), server.getPrivate());
        SignedEnvelope tampered = signed.toBuilder()
                .setSignature(ByteString.copyFrom(new byte[64]))
                .build();
        assertThrows(EnvelopeException.class, () -> new EvidenceRequestVerifier(clock).accept(
                tampered.toByteArray(), codec, server.getPublic(),
                new NonceReplayGuard(clock, Duration.ofMinutes(5)), "retention-session", PLAYER_ID));
    }

    @Test
    void evidenceReplayBudgetCoversMaximumTransferWithoutUsingHeartbeatQuota() {
        MutableClock clock = new MutableClock(1_800_000_000_000L);
        EvidenceRequest request = request(clock.millis() + 120_000L, "request-budget", PLAYER_ID,
                EvidenceCaptureScope.GAME_RENDER_FRAME);
        NonceReplayGuard guard = EvidenceTransferLimits.newRequestReplayGuard(clock, request);
        for (int index = 0; index < ProtocolConstants.MAX_EVIDENCE_REPLAY_ENTRIES_PER_REQUEST; index++) {
            assertTrue(guard.accept("session-budget", ByteBuffer.allocate(Long.BYTES).putLong(index).array()));
        }
        assertFalse(guard.accept("session-budget", ByteBuffer.allocate(Long.BYTES)
                .putLong(ProtocolConstants.MAX_EVIDENCE_REPLAY_ENTRIES_PER_REQUEST).array()));
    }

    @Test
    void successfulGameFrameTransfersAndRejectionNeverCarriesContent() throws Exception {
        MutableClock clock = new MutableClock(1_800_000_000_000L);
        KeyPair keys = Ed25519Keys.generate(new SecureRandom());
        EnvelopeCodec codec = new EnvelopeCodec(clock, new SecureRandom(),
                ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES, Duration.ofSeconds(30));
        EvidenceRequest request = request(clock.millis() + 120_000L, "request-2", PLAYER_ID,
                EvidenceCaptureScope.GAME_RENDER_FRAME);
        byte[] content = new byte[ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES + 7];
        List<byte[]> frames = new EvidenceTransferSender().send(
                "session-2", request, content, 1920, 1080, clock.millis(), 1, codec, keys.getPrivate());
        assertEquals(4, frames.size());
        EvidenceTransferReceiver receiver = new EvidenceTransferReceiver("session-2", request, clock);
        NonceReplayGuard replay = EvidenceTransferLimits.newRequestReplayGuard(clock, request);
        Optional<EvidenceTransferReceiver.CompletedEvidence> completed = Optional.empty();
        for (byte[] frame : frames) {
            Optional<EvidenceTransferReceiver.CompletedEvidence> next =
                    receiver.accept(frame, codec, keys.getPublic(), replay);
            if (next.isPresent()) {
                completed = next;
            }
        }
        assertTrue(completed.isPresent());
        EvidenceTransferReceiver.CompletedEvidence completedEvidence = completed.orElseThrow();
        assertEquals(content.length, completedEvidence.content().length);
        assertEquals(EvidenceType.SCREENSHOT, completedEvidence.type());
        assertEquals(EvidenceCaptureScope.GAME_RENDER_FRAME, completedEvidence.captureScope());
        assertEquals(EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED, completedEvidence.collectionStatus());
        assertEquals(clock.millis(), completedEvidence.capturedAtEpochMs());
        assertEquals(1920, completedEvidence.widthPixels());
        assertEquals(1080, completedEvidence.heightPixels());
        assertTrue(EvidenceTransferLimits.isStrictlyIncreasingUnsigned(Long.MAX_VALUE, Long.MIN_VALUE));
        assertEquals(Long.MIN_VALUE, EvidenceTransferLimits.nextUnsignedSequence(Long.MAX_VALUE));

        EvidenceResponse collected = EvidenceResponse.newBuilder()
                .setEvidenceId(request.getEvidenceId())
                .setType(request.getType())
                .setCaptureScope(request.getCaptureScope())
                .setCapturedAtEpochMs(clock.millis())
                .setContent(ByteString.copyFrom(new byte[] {1, 2, 3}))
                .setContentSha256(ByteString.copyFrom(sha256(new byte[] {1, 2, 3})))
                .setCollectionStatusCode(EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED)
                .setRequestId(request.getRequestId())
                .setPlayerId(request.getPlayerId())
                .build();
        EvidenceTransferLimits.validateResponse(collected, request, clock.millis());

        EvidenceRequest desktop = request(clock.millis() + 60_000L, "request-3", PLAYER_ID,
                EvidenceCaptureScope.DESKTOP);
        var declined = com.ellan.mcace.protocol.generated.EvidenceResponse.newBuilder()
                .setEvidenceId(desktop.getEvidenceId())
                .setType(desktop.getType())
                .setCaptureScope(desktop.getCaptureScope())
                .setCollectionStatusCode(EvidenceCollectionStatus.EVIDENCE_COLLECTION_UNAVAILABLE)
                .setRequestId(desktop.getRequestId())
                .setPlayerId(desktop.getPlayerId())
                .build();
        EvidenceTransferLimits.validateResponse(declined, desktop, clock.millis());
        assertTrue(declined.getContent().isEmpty());
        assertThrows(IllegalArgumentException.class, () -> EvidenceTransferLimits.validateResponse(
                declined.toBuilder().setContent(ByteString.copyFromUtf8("secret")).build(), desktop, clock.millis()));
    }

    @Test
    void senderRejectsTotalAndPixelLimitsBeforeMakingChunkCopies() throws Exception {
        MutableClock clock = new MutableClock(1_800_000_000_000L);
        KeyPair keys = Ed25519Keys.generate(new SecureRandom());
        EnvelopeCodec codec = new EnvelopeCodec(clock, new SecureRandom(),
                ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES, Duration.ofSeconds(30));
        EvidenceRequest request = request(clock.millis() + 120_000L, "request-limits", PLAYER_ID,
                EvidenceCaptureScope.GAME_RENDER_FRAME);
        EvidenceTransferSender sender = new EvidenceTransferSender();
        assertThrows(BoundedPayloadException.class, () -> sender.send(
                "session-limits", request,
                new byte[(int) ProtocolConstants.MAX_EVIDENCE_TOTAL_BYTES + 1],
                1, 1, clock.millis(), 1, codec, keys.getPrivate()));
        assertThrows(BoundedPayloadException.class, () -> sender.send(
                "session-limits", request, new byte[] {1},
                0, 1, clock.millis(), 1, codec, keys.getPrivate()));
        assertThrows(BoundedPayloadException.class, () -> sender.send(
                "session-limits", request, new byte[] {1},
                2001, 2000, clock.millis(), 1, codec, keys.getPrivate()));
    }

    private static EvidenceBegin collectedBegin(long totalBytes, int chunks, int width, int height) {
        return EvidenceBegin.newBuilder()
                .setEvidenceId("e-1")
                .setType(EvidenceType.SCREENSHOT)
                .setCaptureScope(EvidenceCaptureScope.GAME_RENDER_FRAME)
                .setCollectionStatus(EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED)
                .setCapturedAtEpochMs(1)
                .setTotalBytes(totalBytes)
                .setTotalChunks(chunks)
                .setWidthPixels(width)
                .setHeightPixels(height)
                .setContentSha256(ByteString.copyFrom(new byte[32]))
                .setMerkleRootSha256(ByteString.copyFrom(new byte[32]))
                .setRequestId("request-1")
                .setPlayerId(PLAYER_ID)
                .setTransportSequence(1)
                .build();
    }

    private static EvidenceRequest request(long expiresAt, String requestId, String playerId,
            EvidenceCaptureScope scope) {
        return EvidenceRequest.newBuilder()
                .setEvidenceId("evidence-" + requestId)
                .setType(EvidenceType.SCREENSHOT)
                .setExpiresAtEpochMs(expiresAt)
                .setCaptureScope(scope)
                .setRequestId(requestId)
                .setPlayerId(playerId)
                .build();
    }

    private static final String PLAYER_ID = "00000000-0000-0000-0000-000000000001";

    private static byte[] sha256(byte[] content) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(content);
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new AssertionError(exception);
        }
    }

    private static final class MutableClock extends Clock {
        private final AtomicLong now;
        private MutableClock(long now) { this.now = new AtomicLong(now); }
        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return Instant.ofEpochMilli(now.get()); }
        @Override public long millis() { return now.get(); }
    }
}
