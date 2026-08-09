package com.ellan.mcace.core.evidence;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.persistence.EvidenceMetadataDraft;
import com.ellan.mcace.core.persistence.SecurityAuditSink;
import com.ellan.mcace.core.persistence.RiskEventAuditRecord;
import com.ellan.mcace.core.persistence.SessionAuditRecord;
import com.ellan.mcace.core.session.AuthenticatedObservationSession;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.generated.EvidenceBegin;
import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import com.ellan.mcace.protocol.generated.EvidenceChunk;
import com.ellan.mcace.protocol.generated.EvidenceType;
import com.ellan.mcace.protocol.generated.PacketType;
import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class EvidenceRequestRuntimeTest {
    private static final Instant NOW = Instant.parse("2026-08-08T09:00:00Z");

    @Test
    void collectedTransferIsBoundedAndConsumedOnceWithoutRiskCallbacks() throws Exception {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        KeyPair client = Ed25519Keys.generate(new SecureRandom());
        UUID playerId = UUID.randomUUID();
        List<EvidenceMetadataDraft> audit = new ArrayList<>();
        List<EvidenceAuditRecord> summaries = new ArrayList<>();
        List<EvidenceContentStore.EvidenceContent> stored = new ArrayList<>();
        EvidenceContentStore.RetentionDisclosure disclosure = new EvidenceContentStore.RetentionDisclosure(
                true, 3600, "test-policy", "test-purpose");
        EvidenceContentStore retainedStore = new EvidenceContentStore() {
            @Override public StoreResult store(EvidenceContent content) {
                stored.add(content);
                return new StoreResult("memory://test/" + content.evidenceId());
            }
            @Override public RetentionDisclosure retentionDisclosure() { return disclosure; }
        };
        EvidenceRequestRuntime runtime = new EvidenceRequestRuntime(
                clock, new SecureRandom(), server.getPrivate(), auditSink(audit), summaries::add, retainedStore, 1);
        AuthenticatedObservationSession session = new AuthenticatedObservationSession(
                playerId, "session-1", client.getPublic(), NOW.plusSeconds(300));
        EvidenceRequestRuntime.IssuedRequest issued = runtime.issue(
                session, EvidenceRequestSpec.retainedScreenshot(EvidenceCaptureScope.GAME_RENDER_FRAME,
                        "case-1", Duration.ofSeconds(60), 3600, "test-policy", "test-purpose"), "admin")
                .orElseThrow();
        byte[] content = "frame".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] contentHash = sha256(content);
        byte[] chunkHash = sha256(content);
        EvidenceBegin begin = EvidenceBegin.newBuilder()
                .setEvidenceId(issued.request().getEvidenceId()).setRequestId(issued.request().getRequestId())
                .setPlayerId(playerId.toString()).setType(EvidenceType.SCREENSHOT)
                .setCaptureScope(EvidenceCaptureScope.GAME_RENDER_FRAME)
                .setCollectionStatus(EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED)
                .setCapturedAtEpochMs(NOW.toEpochMilli()).setTotalBytes(content.length).setTotalChunks(1)
                .setWidthPixels(1).setHeightPixels(1).setContentSha256(ByteString.copyFrom(contentHash))
                .setMerkleRootSha256(ByteString.copyFrom(chunkHash)).setTransportSequence(1).build();
        EnvelopeCodec codec = new EnvelopeCodec(clock, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES,
                ProtocolConstants.DEFAULT_CLOCK_SKEW);
        byte[] beginFrame = codec.sign(PacketType.EVIDENCE_BEGIN, session.sessionId(), begin.toByteArray(), client.getPrivate())
                .toByteArray();
        assertEquals(EvidenceIngressResult.Status.ACCEPTED, runtime.receive(session, beginFrame).status());
        EvidenceChunk chunk = EvidenceChunk.newBuilder()
                .setEvidenceId(begin.getEvidenceId()).setRequestId(begin.getRequestId()).setPlayerId(playerId.toString())
                .setChunkIndex(0).setContent(ByteString.copyFrom(content)).setChunkSha256(ByteString.copyFrom(chunkHash))
                .setTransportSequence(2).build();
        EvidenceIngressResult chunkResult = runtime.receive(session,
                codec.sign(PacketType.EVIDENCE_CHUNK, session.sessionId(), chunk.toByteArray(), client.getPrivate())
                        .toByteArray());
        assertEquals(EvidenceIngressResult.Status.ACCEPTED, chunkResult.status());
        assertTrue(chunkResult.outboundFrames().isEmpty(), "chunks must not create reverse ACK traffic");
        var commit = com.ellan.mcace.protocol.generated.EvidenceCommit.newBuilder()
                .setEvidenceId(begin.getEvidenceId()).setRequestId(begin.getRequestId()).setPlayerId(playerId.toString())
                .setTotalBytes(content.length).setTotalChunks(1).setContentSha256(ByteString.copyFrom(contentHash))
                .setMerkleRootSha256(ByteString.copyFrom(chunkHash))
                .setCollectionStatus(EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED).setTransportSequence(3).build();
        byte[] commitFrame = codec.sign(PacketType.EVIDENCE_COMMIT, session.sessionId(), commit.toByteArray(), client.getPrivate())
                .toByteArray();
        assertEquals(EvidenceIngressResult.Status.COMPLETE, runtime.receive(session, commitFrame).status());
        assertEquals(0, runtime.outstandingCount());
        assertEquals(1, stored.size());
        assertArrayEquals(content, stored.getFirst().content());
        assertEquals(1, audit.size());
        assertEquals(content.length, audit.getFirst().contentSize());
        assertEquals(1, summaries.size());
        assertEquals(issued.request().getRequestId(), summaries.getFirst().requestId());
        assertEquals(EvidenceCaptureScope.GAME_RENDER_FRAME, summaries.getFirst().captureScope());
        assertEquals(EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED, summaries.getFirst().status());
        assertEquals(EvidenceIngressResult.Status.REJECTED, runtime.receive(session, commitFrame).status());
    }

    @Test
    void declinedResultIsZeroContentAndNeverCallsContentStore() throws Exception {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        KeyPair client = Ed25519Keys.generate(new SecureRandom());
        UUID playerId = UUID.randomUUID();
        int[] storeCalls = {0};
        EvidenceRequestRuntime runtime = new EvidenceRequestRuntime(
                clock, new SecureRandom(), server.getPrivate(), SecurityAuditSink.noop(), content -> {
                    storeCalls[0]++;
                    return new EvidenceContentStore.StoreResult("memory://unexpected");
                }, 1);
        AuthenticatedObservationSession session = new AuthenticatedObservationSession(
                playerId, "session-2", client.getPublic(), NOW.plusSeconds(300));
        EvidenceRequestRuntime.IssuedRequest issued = runtime.issue(
                session, EvidenceRequestSpec.screenshot(EvidenceCaptureScope.DESKTOP, "case-2"), "admin")
                .orElseThrow();
        assertTrue(!issued.request().getRawContentRetained());
        assertEquals(0, issued.request().getRetentionSeconds());
        assertTrue(issued.request().getRetentionPolicyId().isEmpty());
        assertTrue(issued.request().getRetentionPurpose().isEmpty());
        var response = com.ellan.mcace.protocol.generated.EvidenceResponse.newBuilder()
                .setEvidenceId(issued.request().getEvidenceId()).setRequestId(issued.request().getRequestId())
                .setPlayerId(playerId.toString()).setType(EvidenceType.SCREENSHOT)
                .setCaptureScope(EvidenceCaptureScope.DESKTOP)
                .setCollectionStatusCode(EvidenceCollectionStatus.EVIDENCE_COLLECTION_DECLINED)
                .setCapturedAtEpochMs(NOW.toEpochMilli()).build();
        EnvelopeCodec codec = new EnvelopeCodec(clock, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES,
                ProtocolConstants.DEFAULT_CLOCK_SKEW);
        EvidenceIngressResult result = runtime.receive(session,
                codec.sign(PacketType.EVIDENCE_RESPONSE, session.sessionId(), response.toByteArray(), client.getPrivate())
                        .toByteArray());
        assertEquals(EvidenceIngressResult.Status.COMPLETE, result.status());
        assertEquals(0, storeCalls[0]);
        assertEquals(0, runtime.outstandingCount());
    }

    @Test
    void oversizedRawFrameIsRejectedBeforeAllocatingEvidenceState() throws Exception {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        KeyPair client = Ed25519Keys.generate(new SecureRandom());
        AuthenticatedObservationSession session = new AuthenticatedObservationSession(
                UUID.randomUUID(), "session-3", client.getPublic(), NOW.plusSeconds(300));
        EvidenceRequestRuntime runtime = new EvidenceRequestRuntime(
                clock, new SecureRandom(), server.getPrivate(), SecurityAuditSink.noop());
        runtime.issue(session, EvidenceRequestSpec.screenshot(EvidenceCaptureScope.GAME_RENDER_FRAME, "case-3"), "admin")
                .orElseThrow();
        EvidenceIngressResult result = runtime.receive(
                session, new byte[ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES + 1]);
        assertTrue(result.status() == EvidenceIngressResult.Status.REJECTED);
        assertEquals(0, runtime.outstandingCount());
    }

    private static SecurityAuditSink auditSink(List<EvidenceMetadataDraft> audit) {
        return new SecurityAuditSink() {
            @Override public void upsertSession(SessionAuditRecord session) { }
            @Override public void appendRiskEvent(RiskEventAuditRecord event) { }
            @Override public com.ellan.mcace.core.persistence.StoredEvidenceMetadata appendEvidence(
                    EvidenceMetadataDraft evidence) {
                audit.add(evidence);
                return null;
            }
        };
    }

    private static byte[] sha256(byte[] value) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(value);
    }
}
