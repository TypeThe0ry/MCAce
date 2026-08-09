package com.ellan.mcace.runtime;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.client.integrity.ClientIntegrityBundle;
import com.ellan.mcace.client.integrity.ScopeIntegrityManifest;
import com.ellan.mcace.client.policy.VerifiedPolicyCache;
import com.ellan.mcace.client.session.ClientHandshakeEngine;
import com.ellan.mcace.client.session.ClientHandshakeEngine.OutboundFrame;
import com.ellan.mcace.client.session.ClientHandshakeEngine.OutboundChannel;
import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.core.evidence.EvidenceIngressResult;
import com.ellan.mcace.core.evidence.EncryptedEvidenceContentStore;
import com.ellan.mcace.core.evidence.EvidenceRequestRuntime;
import com.ellan.mcace.core.evidence.EvidenceRequestSpec;
import com.ellan.mcace.core.evidence.EvidenceStorageConfiguration;
import com.ellan.mcace.core.evidence.EvidenceStorageMetadata;
import com.ellan.mcace.core.evidence.EvidenceStorageRuntime;
import com.ellan.mcace.core.persistence.EvidenceMetadataDraft;
import com.ellan.mcace.core.persistence.RiskEventAuditRecord;
import com.ellan.mcace.core.persistence.SecurityAuditSink;
import com.ellan.mcace.core.persistence.SessionAuditRecord;
import com.ellan.mcace.core.risk.RiskEngine;
import com.ellan.mcace.core.risk.RiskPolicy;
import com.ellan.mcace.core.session.AuthenticatedObservationSession;
import com.ellan.mcace.core.session.HandshakeAction;
import com.ellan.mcace.core.session.ServerHandshakeCoordinator;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.generated.AuthResult;
import com.ellan.mcace.protocol.generated.ClientHello;
import com.ellan.mcace.protocol.generated.EvidenceAck;
import com.ellan.mcace.protocol.generated.EvidenceAckStatus;
import com.ellan.mcace.protocol.generated.EvidenceBegin;
import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceChunk;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import com.ellan.mcace.protocol.generated.EvidenceCommit;
import com.ellan.mcace.protocol.generated.EvidenceError;
import com.ellan.mcace.protocol.generated.EvidenceErrorCode;
import com.ellan.mcace.protocol.generated.EvidenceRequest;
import com.ellan.mcace.protocol.generated.EvidenceType;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.integrity.IntegrityDigests;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class RuntimeEvidenceEndToEndTest {
    private static final Instant START = Instant.parse("2026-08-09T00:00:00Z");
    private static final byte[] MEMORY_PNG = Base64.getDecoder().decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");

    @TempDir java.nio.file.Path temporaryDirectory;

    @Test
    void windowAndDesktopRequestsCanDeclineOrReportUnavailableWithZeroContentAndAudit() throws Exception {
        Rig rig = newRig();
        PlayerSecuritySnapshot baseline = rig.baseline();

        for (EvidenceCaptureScope scope : List.of(EvidenceCaptureScope.GAME_WINDOW, EvidenceCaptureScope.DESKTOP)) {
            for (EvidenceCollectionStatus status : List.of(
                EvidenceCollectionStatus.EVIDENCE_COLLECTION_DECLINED,
                EvidenceCollectionStatus.EVIDENCE_COLLECTION_UNAVAILABLE)) {
                EvidenceRequestRuntimeView issued = issue(rig, scope, "case-" + scope.name() + "-" + status.name());
                ClientHandshakeEngine.VerifiedEvidenceRequest request =
                        rig.client().receiveEvidenceRequest(issued.frame());
                List<OutboundFrame> responseFrames = rig.client().createEvidenceResponseFrames(request, status);
                assertEquals(1, responseFrames.size());
                assertEquals(OutboundChannel.PAYLOAD, responseFrames.getFirst().channel());

                SignedEnvelope responseEnvelope = SignedEnvelope.parseFrom(responseFrames.getFirst().data());
                var response = com.ellan.mcace.protocol.generated.EvidenceResponse.parseFrom(
                        responseEnvelope.getPayload());
                assertEquals(PacketType.EVIDENCE_RESPONSE, responseEnvelope.getHeader().getPacketType());
                assertTrue(response.getContent().isEmpty());
                assertTrue(response.getContentSha256().isEmpty());
                assertFalse(issued.request().getRawContentRetained());
                assertEquals(0L, issued.request().getRetentionSeconds());

                EvidenceIngressResult result = rig.server().receiveEvidence(rig.playerId(), responseFrames.getFirst().data());
                assertEquals(EvidenceIngressResult.Status.COMPLETE, result.status());
                assertEquals(1, result.outboundFrames().size());
                ClientHandshakeEngine.VerifiedEvidenceAck ack =
                        rig.client().receiveEvidenceAck(result.outboundFrames().getFirst());
                assertEquals(EvidenceAckStatus.EVIDENCE_ACK_COMPLETE, ack.ack().getStatus());
                assertEquals(PacketType.EVIDENCE_RESPONSE, ack.ack().getAcknowledgedPacketType());
                assertEquals(1L, ack.ack().getTransportSequence());
                rig.client().completeEvidenceRequest(request);
                assertEquals(baseline, rig.api().snapshot(rig.playerId()).orElseThrow());
                assertTrue(rig.riskEvents().isEmpty());
            }
        }

        assertEquals(4, rig.audit().size());
        assertTrue(rig.audit().stream().allMatch(entry -> entry.contentSize() == 0));
        assertTrue(rig.audit().stream().allMatch(entry -> entry.contentSha256().length == 32));
    }

    @Test
    void consentedMemoryPngCompletesBeginChunkCommitWithHashesAndMerkleRoot() throws Exception {
        Rig rig = newRig();
        EvidenceRequestRuntimeView issued = issue(
                rig, EvidenceCaptureScope.GAME_RENDER_FRAME, "case-render");
        ClientHandshakeEngine.VerifiedEvidenceRequest request = rig.client().receiveEvidenceRequest(issued.frame());
        ClientHandshakeEngine.EvidenceConsentGrant consent = rig.client().grantEvidenceConsent(request);
        List<OutboundFrame> frames = rig.client().createEvidenceTransferFrames(
                request, consent, rig.clock().millis(), 1, 1, MEMORY_PNG);

        assertEquals(3, frames.size());
        EvidenceBegin begin = payload(frames.get(0), PacketType.EVIDENCE_BEGIN, EvidenceBegin.parser());
        EvidenceChunk chunk = payload(frames.get(1), PacketType.EVIDENCE_CHUNK, EvidenceChunk.parser());
        EvidenceCommit commit = payload(frames.get(2), PacketType.EVIDENCE_COMMIT, EvidenceCommit.parser());
        assertEquals(1L, begin.getTransportSequence());
        assertEquals(2L, chunk.getTransportSequence());
        assertEquals(3L, commit.getTransportSequence());
        assertEquals(request.requestId(), begin.getRequestId());
        assertEquals(request.playerId().toString(), begin.getPlayerId());
        assertArrayEquals(sha256(MEMORY_PNG), begin.getContentSha256().toByteArray());
        assertArrayEquals(sha256(chunk.getContent().toByteArray()), chunk.getChunkSha256().toByteArray());
        assertArrayEquals(chunk.getChunkSha256().toByteArray(), begin.getMerkleRootSha256().toByteArray());
        assertArrayEquals(begin.getContentSha256().toByteArray(), commit.getContentSha256().toByteArray());
        assertArrayEquals(begin.getMerkleRootSha256().toByteArray(), commit.getMerkleRootSha256().toByteArray());

        EvidenceIngressResult beginResult = rig.server().receiveEvidence(rig.playerId(), frames.get(0).data());
        assertEquals(EvidenceIngressResult.Status.ACCEPTED, beginResult.status());
        assertEquals(1, beginResult.outboundFrames().size());
        ClientHandshakeEngine.VerifiedEvidenceAck accepted =
                rig.client().receiveEvidenceAck(beginResult.outboundFrames().getFirst());
        assertEquals(EvidenceAckStatus.EVIDENCE_ACK_ACCEPTED, accepted.ack().getStatus());
        assertEquals(PacketType.EVIDENCE_BEGIN, accepted.ack().getAcknowledgedPacketType());
        assertEquals(1L, accepted.ack().getTransportSequence());

        assertEquals(EvidenceIngressResult.Status.ACCEPTED,
                rig.server().receiveEvidence(rig.playerId(), frames.get(1).data()).status());
        EvidenceIngressResult commitResult = rig.server().receiveEvidence(rig.playerId(), frames.get(2).data());
        assertEquals(EvidenceIngressResult.Status.COMPLETE, commitResult.status());
        ClientHandshakeEngine.VerifiedEvidenceAck complete =
                rig.client().receiveEvidenceAck(commitResult.outboundFrames().getFirst());
        assertEquals(EvidenceAckStatus.EVIDENCE_ACK_COMPLETE, complete.ack().getStatus());
        assertEquals(PacketType.EVIDENCE_COMMIT, complete.ack().getAcknowledgedPacketType());
        assertEquals(3L, complete.ack().getTransportSequence());
        rig.client().completeEvidenceRequest(request);

        assertEquals(1, rig.audit().size());
        EvidenceMetadataDraft audit = rig.audit().getFirst();
        assertEquals(MEMORY_PNG.length, audit.contentSize());
        assertArrayEquals(sha256(MEMORY_PNG), audit.contentSha256());
        assertEquals(rig.baseline(), rig.api().snapshot(rig.playerId()).orElseThrow());
        assertTrue(rig.riskEvents().isEmpty());
    }

    @Test
    void retainedDisclosureStoresOnlyEncryptedBytesAndSweepsAfterExpiry() throws Exception {
        Rig rig = newRig();
        Path retainedRoot = temporaryDirectory.resolve("retained-evidence-root");
        Path retainedKey = temporaryDirectory.resolve("retained-evidence.key");
        EvidenceStorageConfiguration configuration = new EvidenceStorageConfiguration(
                true, true, retainedRoot, retainedKey, 2, "integration-short-v1",
                "short-lived game-render review", 1_048_576, 8, 2_097_152);
        List<EvidenceMetadataDraft> storageAudit = new ArrayList<>();
        List<RiskEventAuditRecord> storageRiskEvents = new ArrayList<>();
        EvidenceStorageRuntime storage = configuration.createRuntime(
                rig.clock(), new SecureRandom(), ignored -> { });
        assertTrue(Files.exists(retainedKey));
        assertEquals(2L, storage.adminService().status().retentionSeconds());
        assertEquals("integration-short-v1", storage.adminService().status().retentionPolicyId());
        EvidenceRequestRuntime runtime = new EvidenceRequestRuntime(
                rig.clock(), new SecureRandom(), rig.serverIdentity().getPrivate(),
                auditSink(storageAudit, storageRiskEvents), storage.contentStore(), 1);

        EvidenceRequestRuntime.IssuedRequest issued = runtime.issue(
                rig.observationSession(),
                EvidenceRequestSpec.retainedScreenshot(
                        EvidenceCaptureScope.GAME_RENDER_FRAME, "case-retained", Duration.ofSeconds(30),
                        2, "integration-short-v1", "short-lived game-render review"),
                "integration-retained").orElseThrow();
        assertTrue(issued.request().getRawContentRetained());
        assertEquals(2L, issued.request().getRetentionSeconds());
        assertEquals("integration-short-v1", issued.request().getRetentionPolicyId());
        assertEquals("short-lived game-render review", issued.request().getRetentionPurpose());

        ClientHandshakeEngine.VerifiedEvidenceRequest request =
                rig.client().receiveEvidenceRequest(issued.encodedFrame());
        assertTrue(request.rawContentRetained());
        assertEquals(2L, request.retentionSeconds());
        assertEquals("integration-short-v1", request.retentionPolicyId());
        assertEquals("short-lived game-render review", request.retentionPurpose());
        List<OutboundFrame> frames = sendMemoryTransfer(rig, runtime, request);
        EvidenceBegin begin = payload(frames.getFirst(), PacketType.EVIDENCE_BEGIN, EvidenceBegin.parser());
        UUID evidenceId = UUID.fromString(request.evidenceId());
        EvidenceStorageMetadata metadata = new EvidenceStorageMetadata(
                evidenceId, rig.playerId(), rig.sessionId(), request.requestId(), request.caseId(),
                request.type(), request.captureScope(), EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED,
                Instant.ofEpochMilli(begin.getCapturedAtEpochMs()), begin.getWidthPixels(), begin.getHeightPixels(),
                begin.getTotalChunks(), begin.getContentSha256().toByteArray(), begin.getMerkleRootSha256().toByteArray(),
                request.retentionSeconds(), request.retentionPolicyId(), request.retentionPurpose());
        assertEquals(1, storage.adminService().status().fileCount());
        Path encryptedFile;
        try (var files = Files.list(retainedRoot)) {
            encryptedFile = files.filter(path -> path.getFileName().toString().endsWith(".mce"))
                    .findFirst().orElseThrow();
        }
        byte[] encryptedEnvelope = Files.readAllBytes(encryptedFile);
        assertFalse(contains(encryptedEnvelope, MEMORY_PNG), "raw PNG must not be present in encrypted storage");
        EncryptedEvidenceContentStore encryptedStore =
                (EncryptedEvidenceContentStore) storage.contentStore();
        assertArrayEquals(MEMORY_PNG, encryptedStore.read(evidenceId, metadata));

        EvidenceStorageMetadata wrongAad = new EvidenceStorageMetadata(
                evidenceId, rig.playerId(), rig.sessionId(), request.requestId(), "wrong-case",
                request.type(), request.captureScope(), EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED,
                metadata.capturedAt(), metadata.widthPixels(), metadata.heightPixels(), metadata.totalChunks(),
                metadata.contentSha256(), metadata.merkleRootSha256(), metadata.retentionSeconds(),
                metadata.retentionPolicyId(), metadata.retentionPurpose());
        assertThrows(Exception.class, () -> encryptedStore.read(evidenceId, wrongAad));

        byte[] tamperedCiphertext = encryptedEnvelope.clone();
        tamperedCiphertext[tamperedCiphertext.length - 1] ^= 1;
        Files.write(encryptedFile, tamperedCiphertext, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
        assertThrows(Exception.class, () -> encryptedStore.read(evidenceId, metadata));
        Files.write(encryptedFile, encryptedEnvelope, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);

        rig.clock().advance(Duration.ofSeconds(3));
        assertEquals(1, storage.adminService().sweepExpired(8));
        assertFalse(Files.exists(encryptedFile));
        assertEquals(1, storageAudit.size());
        assertEquals(MEMORY_PNG.length, storageAudit.getFirst().contentSize());
        assertArrayEquals(sha256(MEMORY_PNG), storageAudit.getFirst().contentSha256());
        assertTrue(storageRiskEvents.isEmpty());
        assertEquals(rig.baseline(), rig.api().snapshot(rig.playerId()).orElseThrow());
        assertTrue(rig.riskEvents().isEmpty());
    }

    @Test
    void defaultDiscardTransferCreatesNoEvidenceKeyConfigOrRawFile() throws Exception {
        Rig rig = newRig();
        Path discardWorkspace = temporaryDirectory.resolve("default-discard-evidence");
        Path configPath = discardWorkspace.resolve("evidence-storage.properties");
        Path keyPath = discardWorkspace.resolve("evidence-storage.key");
        EvidenceStorageRuntime disabled = EvidenceStorageRuntime.disabled(rig.clock(), ignored -> { });
        List<EvidenceMetadataDraft> discardAudit = new ArrayList<>();
        List<RiskEventAuditRecord> discardRiskEvents = new ArrayList<>();
        EvidenceRequestRuntime runtime = new EvidenceRequestRuntime(
                rig.clock(), new SecureRandom(), rig.serverIdentity().getPrivate(),
                auditSink(discardAudit, discardRiskEvents), disabled.contentStore(), 1);
        EvidenceRequestRuntime.IssuedRequest issued = runtime.issue(
                rig.observationSession(),
                new EvidenceRequestSpec(EvidenceType.SCREENSHOT, EvidenceCaptureScope.GAME_RENDER_FRAME,
                        List.of(), "case-discard", Duration.ofSeconds(30)),
                "integration-discard").orElseThrow();
        assertFalse(issued.request().getRawContentRetained());
        assertEquals(0L, issued.request().getRetentionSeconds());
        ClientHandshakeEngine.VerifiedEvidenceRequest request =
                rig.client().receiveEvidenceRequest(issued.encodedFrame());
        assertFalse(request.rawContentRetained());
        sendMemoryTransfer(rig, runtime, request);

        assertFalse(Files.exists(configPath));
        assertFalse(Files.exists(keyPath));
        assertFalse(Files.exists(discardWorkspace));
        assertTrue(discardAudit.size() == 1 && discardAudit.getFirst().contentSize() == MEMORY_PNG.length);
        assertTrue(discardRiskEvents.isEmpty());
        assertTrue(rig.riskEvents().isEmpty());
        assertEquals(rig.baseline(), rig.api().snapshot(rig.playerId()).orElseThrow());
    }

    @Test
    void tamperedChunkReorderedChunkAndReplayAreRejectedWithoutRiskChange() throws Exception {
        Rig tampered = newRig();
        PreparedTransfer tamperedTransfer = preparedTransfer(tampered, "case-tamper");
        assertEquals(EvidenceIngressResult.Status.ACCEPTED,
                tampered.server().receiveEvidence(tampered.playerId(), tamperedTransfer.frames().get(0).data()).status());
        byte[] altered = tamperedTransfer.frames().get(1).data().clone();
        altered[altered.length - 1] ^= 1;
        EvidenceIngressResult tamperedResult = tampered.server().receiveEvidence(tampered.playerId(), altered);
        assertEquals(EvidenceIngressResult.Status.REJECTED, tamperedResult.status());
        assertEvidenceError(tamperedResult, tamperedTransfer.request(), PacketType.EVIDENCE_CHUNK);
        tampered.client().receiveEvidenceError(tamperedResult.outboundFrames().getFirst());
        tampered.client().cancelEvidenceRequest(tamperedTransfer.request());
        assertEquals(tampered.baseline(), tampered.api().snapshot(tampered.playerId()).orElseThrow());
        assertTrue(tampered.audit().isEmpty());
        assertTrue(tampered.riskEvents().isEmpty());

        Rig reordered = newRig();
        PreparedTransfer reorderedTransfer = preparedTransfer(reordered, "case-order");
        EvidenceIngressResult reorderedResult = reordered.server().receiveEvidence(
                reordered.playerId(), reorderedTransfer.frames().get(1).data());
        assertEquals(EvidenceIngressResult.Status.REJECTED, reorderedResult.status());
        assertEvidenceError(reorderedResult, reorderedTransfer.request(), PacketType.EVIDENCE_CHUNK);
        reordered.client().receiveEvidenceError(reorderedResult.outboundFrames().getFirst());
        reordered.client().cancelEvidenceRequest(reorderedTransfer.request());
        assertEquals(reordered.baseline(), reordered.api().snapshot(reordered.playerId()).orElseThrow());
        assertTrue(reordered.riskEvents().isEmpty());

        Rig replayed = newRig();
        PreparedTransfer replayedTransfer = preparedTransfer(replayed, "case-replay");
        assertEquals(EvidenceIngressResult.Status.ACCEPTED,
                replayed.server().receiveEvidence(replayed.playerId(), replayedTransfer.frames().get(0).data()).status());
        EvidenceIngressResult replayResult = replayed.server().receiveEvidence(
                replayed.playerId(), replayedTransfer.frames().get(0).data());
        assertEquals(EvidenceIngressResult.Status.REPLAYED, replayResult.status());
        assertEvidenceError(replayResult, replayedTransfer.request(), PacketType.EVIDENCE_BEGIN);
        replayed.client().receiveEvidenceError(replayResult.outboundFrames().getFirst());
        replayed.client().cancelEvidenceRequest(replayedTransfer.request());
        assertEquals(replayed.baseline(), replayed.api().snapshot(replayed.playerId()).orElseThrow());
        assertTrue(replayed.riskEvents().isEmpty());
    }

    @Test
    void expiryAndDisconnectCancelOutstandingEvidenceWithoutAdmissionOrPunishment() throws Exception {
        Rig expired = newRig();
        EvidenceRequestRuntimeView issued = issue(
                expired, EvidenceCaptureScope.GAME_RENDER_FRAME, "case-expiry", Duration.ofSeconds(1));
        ClientHandshakeEngine.VerifiedEvidenceRequest request = expired.client().receiveEvidenceRequest(issued.frame());
        List<OutboundFrame> response = expired.client().createEvidenceResponseFrames(
                request, EvidenceCollectionStatus.EVIDENCE_COLLECTION_DECLINED);
        expired.clock().advance(Duration.ofSeconds(2));
        EvidenceIngressResult expiryResult = expired.server().receiveEvidence(
                expired.playerId(), response.getFirst().data());
        assertEquals(EvidenceIngressResult.Status.EXPIRED, expiryResult.status());
        assertEvidenceError(expiryResult, request, PacketType.EVIDENCE_RESPONSE);
        expired.client().receiveEvidenceError(expiryResult.outboundFrames().getFirst());
        expired.client().cancelEvidenceRequest(request);
        assertEquals(expired.baseline(), expired.api().snapshot(expired.playerId()).orElseThrow());
        assertTrue(expired.audit().isEmpty());
        assertTrue(expired.riskEvents().isEmpty());

        Rig disconnected = newRig();
        EvidenceRequestRuntimeView disconnectIssued = issue(
                disconnected, EvidenceCaptureScope.GAME_RENDER_FRAME, "case-disconnect");
        ClientHandshakeEngine.VerifiedEvidenceRequest disconnectRequest =
                disconnected.client().receiveEvidenceRequest(disconnectIssued.frame());
        assertTrue(disconnected.server().cancelEvidenceRequest(disconnected.playerId()));
        assertFalse(disconnected.server().cancelEvidenceRequest(disconnected.playerId()));
        disconnected.client().cancelEvidenceRequest(disconnectRequest);
        assertEquals(EvidenceIngressResult.Status.REJECTED, disconnected.server().receiveEvidence(
                disconnected.playerId(), new byte[] {1}).status());
        assertEquals(disconnected.baseline(), disconnected.api().snapshot(disconnected.playerId()).orElseThrow());
        assertTrue(disconnected.audit().isEmpty());
        assertTrue(disconnected.riskEvents().isEmpty());
    }

    @Test
    void serverOnlyPacketInjectedTowardServerIsRejectedWithoutRiskOrAudit() throws Exception {
        Rig rig = newRig();
        EvidenceRequestRuntimeView issued = issue(rig, EvidenceCaptureScope.GAME_RENDER_FRAME, "case-inject");
        ClientHandshakeEngine.VerifiedEvidenceRequest verifiedRequest =
                rig.client().receiveEvidenceRequest(issued.frame());
        EvidenceAck injected = EvidenceAck.newBuilder()
                .setRequestId(issued.request().getRequestId())
                .setEvidenceId(issued.request().getEvidenceId())
                .setAcknowledgedPacketType(PacketType.EVIDENCE_RESPONSE)
                .setStatus(EvidenceAckStatus.EVIDENCE_ACK_COMPLETE)
                .setTransportSequence(1)
                .build();
        EnvelopeCodec codec = new EnvelopeCodec(
                rig.clock(), new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES,
                ProtocolConstants.DEFAULT_CLOCK_SKEW);
        byte[] injectedFrame = codec.sign(
                PacketType.EVIDENCE_ACK, rig.sessionId(), injected.toByteArray(), rig.serverIdentity().getPrivate())
                .toByteArray();
        EvidenceIngressResult result = rig.server().receiveEvidence(rig.playerId(), injectedFrame);
        assertEquals(EvidenceIngressResult.Status.REJECTED, result.status());
        assertEvidenceError(result, verifiedRequest, PacketType.EVIDENCE_ACK);
        rig.client().receiveEvidenceError(result.outboundFrames().getFirst());
        rig.client().cancelEvidenceRequest(verifiedRequest);
        assertEquals(rig.baseline(), rig.api().snapshot(rig.playerId()).orElseThrow());
        assertTrue(rig.audit().isEmpty());
        assertTrue(rig.riskEvents().isEmpty());
    }

    private EvidenceRequestRuntimeView issue(Rig rig, EvidenceCaptureScope scope, String caseId) throws Exception {
        return issue(rig, scope, caseId, Duration.ofMinutes(2));
    }

    private EvidenceRequestRuntimeView issue(Rig rig, EvidenceCaptureScope scope, String caseId, Duration ttl)
            throws Exception {
        EvidenceRequestRuntimeView issued = new EvidenceRequestRuntimeView(
                rig.server().issueEvidenceRequest(
                        rig.playerId(), new EvidenceRequestSpec(
                                EvidenceType.SCREENSHOT, scope, List.of(), caseId, ttl), "integration-test")
                        .orElseThrow());
        assertFalse(issued.request().getRawContentRetained());
        assertEquals(0L, issued.request().getRetentionSeconds());
        assertNotNull(issued.request().getRequestId());
        return issued;
    }

    private List<OutboundFrame> sendMemoryTransfer(
            Rig rig, EvidenceRequestRuntime runtime, ClientHandshakeEngine.VerifiedEvidenceRequest request)
            throws Exception {
        ClientHandshakeEngine.EvidenceConsentGrant consent = rig.client().grantEvidenceConsent(request);
        List<OutboundFrame> frames = rig.client().createEvidenceTransferFrames(
                request, consent, rig.clock().millis(), 1, 1, MEMORY_PNG);
        assertEquals(3, frames.size());
        EvidenceIngressResult beginResult = runtime.receive(
                rig.observationSession(), frames.get(0).data());
        assertEquals(EvidenceIngressResult.Status.ACCEPTED, beginResult.status());
        assertEquals(1, beginResult.outboundFrames().size());
        ClientHandshakeEngine.VerifiedEvidenceAck accepted =
                rig.client().receiveEvidenceAck(beginResult.outboundFrames().getFirst());
        assertEquals(EvidenceAckStatus.EVIDENCE_ACK_ACCEPTED, accepted.ack().getStatus());
        assertEquals(PacketType.EVIDENCE_BEGIN, accepted.ack().getAcknowledgedPacketType());
        assertEquals(1L, accepted.ack().getTransportSequence());

        assertEquals(EvidenceIngressResult.Status.ACCEPTED,
                runtime.receive(rig.observationSession(), frames.get(1).data()).status());
        EvidenceIngressResult commitResult = runtime.receive(
                rig.observationSession(), frames.get(2).data());
        assertEquals(EvidenceIngressResult.Status.COMPLETE, commitResult.status());
        assertEquals(1, commitResult.outboundFrames().size());
        ClientHandshakeEngine.VerifiedEvidenceAck complete =
                rig.client().receiveEvidenceAck(commitResult.outboundFrames().getFirst());
        assertEquals(EvidenceAckStatus.EVIDENCE_ACK_COMPLETE, complete.ack().getStatus());
        assertEquals(PacketType.EVIDENCE_COMMIT, complete.ack().getAcknowledgedPacketType());
        assertEquals(3L, complete.ack().getTransportSequence());
        rig.client().completeEvidenceRequest(request);
        return frames;
    }

    private PreparedTransfer preparedTransfer(Rig rig, String caseId) throws Exception {
        EvidenceRequestRuntimeView issued = issue(rig, EvidenceCaptureScope.GAME_RENDER_FRAME, caseId);
        ClientHandshakeEngine.VerifiedEvidenceRequest request = rig.client().receiveEvidenceRequest(issued.frame());
        ClientHandshakeEngine.EvidenceConsentGrant consent = rig.client().grantEvidenceConsent(request);
        return new PreparedTransfer(request, rig.client().createEvidenceTransferFrames(
                request, consent, rig.clock().millis(), 1, 1, MEMORY_PNG));
    }

    private Rig newRig() throws Exception {
        MutableClock clock = new MutableClock(START);
        RuntimeFixture fixture = RuntimeFixture.create(clock);
        UUID playerId = UUID.nameUUIDFromBytes(("runtime-evidence-" + UUID.randomUUID())
                .getBytes(StandardCharsets.UTF_8));
        InMemoryMCAceApi api = new InMemoryMCAceApi();
        List<EvidenceMetadataDraft> audit = new ArrayList<>();
        List<RiskEventAuditRecord> riskEvents = new ArrayList<>();
        SecurityAuditSink auditSink = auditSink(audit, riskEvents);
        ServerHandshakeCoordinator server = new ServerHandshakeCoordinator(
                clock, new SecureRandom(), fixture.serverIdentity(), new RiskEngine(RiskPolicy.defaults()), api,
                Duration.ofSeconds(3), fixture::policy, auditSink, ignored -> { });
        byte[] serverHello = server.begin(playerId);
        ClientHandshakeEngine client = new ClientHandshakeEngine(
                playerId, "runtime-integration", "1.21.1", "runtime-good", LoaderType.FABRIC,
                fixture.serverIdentity().getPublic(), clock, new SecureRandom());
        client.prepareServerHello(serverHello, "runtime-evidence", new VerifiedPolicyCache(
                temporaryDirectory.resolve(playerId.toString()), clock));
        List<byte[]> authentication = client.createAuthentication(emptyBundle(clock));
        assertTrue(server.receive(playerId, authentication.get(0)).outboundFrames().isEmpty());
        HandshakeAction authenticated = server.receive(playerId, authentication.get(1));
        AuthResult authResult = client.receiveAuthResult(authenticated.outboundFrames().getFirst());
        assertTrue(authResult.getAccepted());
        PlayerSecuritySnapshot baseline = api.snapshot(playerId).orElseThrow();
        String sessionId = SignedEnvelope.parseFrom(serverHello).getHeader().getSessionId();
        ClientHello clientHello = ClientHello.parseFrom(
                SignedEnvelope.parseFrom(authentication.getFirst()).getPayload());
        AuthenticatedObservationSession observationSession = new AuthenticatedObservationSession(
                playerId, sessionId, Ed25519Keys.decodePublic(clientHello.getPublicKeyX509().toByteArray()),
                clock.instant().plus(Duration.ofMinutes(10)));
        return new Rig(clock, fixture.serverIdentity(), server, client, api, audit, riskEvents,
                baseline, playerId, sessionId, observationSession);
    }

    private static ClientIntegrityBundle emptyBundle(Clock clock) throws Exception {
        return ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, clock.instant(), List.of(), IntegrityDigests.scopeRoot(List.of()))));
    }

    private static SecurityAuditSink auditSink(
            List<EvidenceMetadataDraft> audit, List<RiskEventAuditRecord> riskEvents) {
        return new SecurityAuditSink() {
            @Override public void upsertSession(SessionAuditRecord session) { }
            @Override public void appendRiskEvent(RiskEventAuditRecord event) { riskEvents.add(event); }
            @Override public com.ellan.mcace.core.persistence.StoredEvidenceMetadata appendEvidence(
                    EvidenceMetadataDraft evidence) {
                audit.add(evidence);
                return null;
            }
        };
    }

    private static <T extends com.google.protobuf.Message> T payload(
            OutboundFrame frame, PacketType expectedType, com.google.protobuf.Parser<T> parser) throws Exception {
        assertEquals(OutboundChannel.PAYLOAD, frame.channel());
        SignedEnvelope envelope = SignedEnvelope.parseFrom(frame.data());
        assertEquals(expectedType, envelope.getHeader().getPacketType());
        return parser.parseFrom(envelope.getPayload());
    }

    private static void assertEvidenceError(
            EvidenceIngressResult result,
            ClientHandshakeEngine.VerifiedEvidenceRequest request,
            PacketType rejectedType) throws Exception {
        assertEquals(1, result.outboundFrames().size());
        SignedEnvelope envelope = SignedEnvelope.parseFrom(result.outboundFrames().getFirst());
        assertEquals(PacketType.EVIDENCE_ERROR, envelope.getHeader().getPacketType());
        EvidenceError error = EvidenceError.parseFrom(envelope.getPayload());
        assertEquals(request.requestId(), error.getRequestId());
        assertEquals(request.evidenceId(), error.getEvidenceId());
        assertEquals(rejectedType, error.getRejectedPacketType());
        assertTrue(error.getTransportSequence() > 0L);
        assertFalse(error.getCode() == EvidenceErrorCode.EVIDENCE_ERROR_CODE_UNSPECIFIED);
    }

    private static byte[] sha256(byte[] bytes) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(bytes);
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        if (needle.length == 0) return true;
        for (int start = 0; start <= haystack.length - needle.length; start++) {
            boolean match = true;
            for (int offset = 0; offset < needle.length; offset++) {
                if (haystack[start + offset] != needle[offset]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }

    private record EvidenceRequestRuntimeView(
            com.ellan.mcace.core.evidence.EvidenceRequestRuntime.IssuedRequest issued) {
        EvidenceRequest request() { return issued.request(); }
        byte[] frame() { return issued.encodedFrame(); }
    }

    private record PreparedTransfer(
            ClientHandshakeEngine.VerifiedEvidenceRequest request, List<OutboundFrame> frames) { }

    private record Rig(
            MutableClock clock,
            java.security.KeyPair serverIdentity,
            ServerHandshakeCoordinator server,
            ClientHandshakeEngine client,
            InMemoryMCAceApi api,
            List<EvidenceMetadataDraft> audit,
            List<RiskEventAuditRecord> riskEvents,
            PlayerSecuritySnapshot baseline,
            UUID playerId,
            String sessionId,
            AuthenticatedObservationSession observationSession) { }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) { this.instant = instant; }

        void advance(Duration duration) { instant = instant.plus(duration); }
        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return instant; }
    }
}
