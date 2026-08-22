package com.ellan.mcace.client.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.client.integrity.ClientIntegrityBundle;
import com.ellan.mcace.client.integrity.IntegrityEntry;
import com.ellan.mcace.client.integrity.ScopeIntegrityManifest;
import com.ellan.mcace.client.policy.VerifiedPolicyCache;
import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.ArtifactType;
import com.ellan.mcace.core.disposition.Confidence;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.IntegrityScopeRule;
import com.ellan.mcace.protocol.generated.AuthRequest;
import com.ellan.mcace.protocol.generated.AuthResult;
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
import com.ellan.mcace.protocol.generated.EvidenceResponse;
import com.ellan.mcace.protocol.generated.EvidenceType;
import com.ellan.mcace.protocol.generated.Heartbeat;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.ServerHello;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.ellan.mcace.protocol.heartbeat.HeartbeatSessionStateMachine;
import com.ellan.mcace.protocol.transport.BoundedPayloadTransferReceiver;
import com.google.protobuf.ByteString;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class ClientHandshakeEngineBudgetTest {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-08-08T08:00:00Z"), ZoneOffset.UTC);
    @TempDir Path temporaryDirectory;

    @Test
    void rejectsAnAuthenticationManifestThatCannotFitOneSignedFrame() throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = readyClient(server);

        assertThrows(EnvelopeException.class, () -> client.createAuthentication(oversizedBundle()));
    }

    @Test
    void enrichesOnlyBundleMappedLowConfidenceClientModMetadata() throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = readyClient(server);
        byte[] hash = new byte[32];
        java.util.Arrays.fill(hash, (byte) 7);
        ClientIntegrityBundle bundle = ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, CLOCK.instant(),
                List.of(new IntegrityEntry("example.jar", 4, hash)), new byte[32])));
        ArtifactObservation metadata = new ArtifactObservation(
                ArtifactType.MOD,
                "example.mod",
                "1.2.3",
                java.util.HexFormat.of().formatHex(hash),
                java.util.Map.of("scope", "mods", "artifact_path", "example.jar"),
                ObservationOrigin.CLIENT_REPORTED,
                Confidence.LOW,
                false);

        List<byte[]> frames = client.createAuthentication(bundle, List.of(metadata));
        AuthRequest authentication = AuthRequest.parseFrom(
                SignedEnvelope.parseFrom(frames.get(1)).getPayload());

        assertEquals("example.mod", authentication.getMods(0).getId());
        assertEquals("1.2.3", authentication.getMods(0).getVersion());
        ArtifactObservation outsideBundle = new ArtifactObservation(
                ArtifactType.MOD,
                "example.mod",
                "1.2.3",
                java.util.HexFormat.of().formatHex(hash),
                java.util.Map.of("scope", "mods", "artifact_path", "other.jar"),
                ObservationOrigin.CLIENT_REPORTED,
                Confidence.LOW,
                false);
        assertThrows(EnvelopeException.class, () -> client.createAuthentication(bundle, List.of(outsideBundle)));
    }

    @Test
    void rejectsNonCanonicalSelectedPackIdsBeforeSigningTheSnapshot() throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = readyClient(server);
        ClientIntegrityBundle bundle = ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, CLOCK.instant(), List.of(), new byte[32])));
        assertThrows(EnvelopeException.class, () -> client.createAuthenticationFrames(
                bundle, List.of(), List.of(" file/xray.zip"), List.of()));
        assertThrows(EnvelopeException.class, () -> client.createAuthenticationFrames(
                bundle, List.of(), java.util.Arrays.asList("xray.zip", null), List.of()));
    }

    @Test
    void fragmentsLargeAuthenticationAndReceiverReassemblesTheSameAuthRequest() throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = readyClient(server);

        List<ClientHandshakeEngine.OutboundFrame> frames = client.createAuthenticationFrames(fragmentedBundle());
        assertEquals(ClientHandshakeEngine.OutboundChannel.HANDSHAKE, frames.getFirst().channel());
        assertTrue(frames.stream().allMatch(frame -> frame.data().length <= ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES));
        List<ClientHandshakeEngine.OutboundFrame> payloadFrames = frames.stream()
                .filter(frame -> frame.channel() == ClientHandshakeEngine.OutboundChannel.PAYLOAD)
                .toList();
        assertTrue(payloadFrames.size() > 3);
        BoundedPayloadTransferReceiver receiver = new BoundedPayloadTransferReceiver("budget-session", CLOCK, Duration.ofMinutes(1));
        Optional<BoundedPayloadTransferReceiver.CompletedPayload> completed = Optional.empty();
        for (ClientHandshakeEngine.OutboundFrame frame : payloadFrames) {
            completed = receiver.acceptVerified(SignedEnvelope.parseFrom(frame.data()));
        }

        BoundedPayloadTransferReceiver.CompletedPayload transfer = completed.orElseThrow();
        AuthRequest authentication = AuthRequest.parseFrom(transfer.content());
        assertEquals(512, authentication.getModsCount());
        assertEquals(authentication.getManifestRootSha256(), ByteString.copyFrom(transfer.manifestRootSha256()));
    }

    @Test
    void createsBoundedSequentialHeartbeatOnlyAfterSignedAcceptedAuthentication() throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = readyClient(server);
        ClientIntegrityBundle bundle = ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, CLOCK.instant(),
                List.of(new IntegrityEntry("example.jar", 4, new byte[32])), new byte[32])));
        List<byte[]> authenticationFrames = client.createAuthentication(bundle);
        AuthRequest authentication = AuthRequest.parseFrom(
                SignedEnvelope.parseFrom(authenticationFrames.get(1)).getPayload());
        com.ellan.mcace.protocol.generated.ClientHello clientHello =
                com.ellan.mcace.protocol.generated.ClientHello.parseFrom(
                        SignedEnvelope.parseFrom(authenticationFrames.getFirst()).getPayload());

        assertFalse(client.heartbeatReady());
        assertThrows(EnvelopeException.class, client::createHeartbeat);

        client.receiveAuthResult(authResult(server, true));
        assertTrue(client.heartbeatReady());
        SignedEnvelope first = SignedEnvelope.parseFrom(client.createHeartbeat());
        SignedEnvelope second = SignedEnvelope.parseFrom(client.createHeartbeat());
        Heartbeat firstPayload = Heartbeat.parseFrom(first.getPayload());
        Heartbeat secondPayload = Heartbeat.parseFrom(second.getPayload());

        assertEquals(PacketType.HEARTBEAT, first.getHeader().getPacketType());
        assertEquals(1L, firstPayload.getSequence());
        assertEquals(2L, secondPayload.getSequence());
        assertEquals(TrustLevel.VERIFIED, firstPayload.getClientStatus());
        assertEquals(authentication.getManifestRootSha256(), firstPayload.getManifestRootSha256());
        assertEquals(authentication.getPolicySequence(), firstPayload.getPolicySequence());
        assertEquals(authentication.getPolicySha256(), firstPayload.getPolicySha256());
        assertEquals(bundle.aggregateRootSha256().length, firstPayload.getAggregateRootSha256().size());
        assertTrue(first.toByteArray().length <= ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES);
        HeartbeatSessionStateMachine receiver = new HeartbeatSessionStateMachine(
                "budget-session",
                authentication.getManifestRootSha256().toByteArray(),
                authentication.getPolicySequence(),
                authentication.getPolicySha256().toByteArray(),
                bundle.aggregateRootSha256(),
                CLOCK);
        EnvelopeCodec receiverCodec = new EnvelopeCodec(
                CLOCK, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES, ProtocolConstants.DEFAULT_CLOCK_SKEW);
        receiver.accept(first.toByteArray(), receiverCodec,
                Ed25519Keys.decodePublic(clientHello.getPublicKeyX509().toByteArray()),
                new NonceReplayGuard(CLOCK, ProtocolConstants.DEFAULT_REPLAY_WINDOW));
        receiver.accept(second.toByteArray(), receiverCodec,
                Ed25519Keys.decodePublic(clientHello.getPublicKeyX509().toByteArray()),
                new NonceReplayGuard(CLOCK, ProtocolConstants.DEFAULT_REPLAY_WINDOW));
        assertThrows(EnvelopeException.class, () -> client.receiveAuthResult(authResult(server, true)));
    }

    @Test
    void declinedAuthenticationNeverEnablesHeartbeat() throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = readyClient(server);
        client.createAuthentication(ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, CLOCK.instant(), List.of(), new byte[32]))));

        client.receiveAuthResult(authResult(server, false));

        assertFalse(client.heartbeatReady());
        assertThrows(EnvelopeException.class, client::createHeartbeat);
    }

    @Test
    void acceptedHeartbeatContinuesAfterSignedAuthResultExpiry() throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        MutableClock clock = new MutableClock(CLOCK.instant());
        ClientHandshakeEngine client = readyClient(server, clock);
        client.createAuthentication(ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, CLOCK.instant(), List.of(), new byte[32]))));
        client.receiveAuthResult(authResult(server, true, clock, Duration.ofSeconds(30)));

        assertTrue(client.heartbeatReady());
        clock.advance(Duration.ofSeconds(30));
        assertTrue(client.heartbeatReady());
        assertEquals(1L, Heartbeat.parseFrom(SignedEnvelope.parseFrom(client.createHeartbeat()).getPayload()).getSequence());
    }

    @Test
    void expiredSignedAuthResultIsStillRejectedAtReceipt() throws Exception {
        KeyPair server = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        MutableClock clock = new MutableClock(CLOCK.instant());
        ClientHandshakeEngine client = readyClient(server, clock);
        client.createAuthentication(ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, CLOCK.instant(), List.of(), new byte[32]))));

        assertThrows(EnvelopeException.class,
                () -> client.receiveAuthResult(authResult(server, true, clock, Duration.ofSeconds(-1))));
        assertTrue(client.receiveAuthResult(authResult(server, true, clock, Duration.ofMinutes(1))).getAccepted());
    }

    @Test
    void acceptsOnlySignedCurrentPlayerEvidenceRequestAndBindsEveryTransferFrame() throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = readyClient(server);
        client.createAuthentication(ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, CLOCK.instant(), List.of(), new byte[32]))));
        client.receiveAuthResult(authResult(server, true));
        EvidenceRequest request = EvidenceRequest.newBuilder()
                .setEvidenceId("evidence-1")
                .setRequestId("request-1")
                .setPlayerId(UUID.randomUUID().toString())
                .setType(EvidenceType.SCREENSHOT)
                .setCaptureScope(EvidenceCaptureScope.GAME_RENDER_FRAME)
                .setExpiresAtEpochMs(CLOCK.millis() + Duration.ofMinutes(1).toMillis())
                .setCaseId("case-1")
                .build();
        // Use the actual authenticated player's UUID; the first value above deliberately proves
        // that the verifier never accepts an unrelated player id.
        request = request.toBuilder().setPlayerId(clientPlayerId(client)).build();
        byte[] encodedRequest = new EnvelopeCodec(
                CLOCK, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES, ProtocolConstants.DEFAULT_CLOCK_SKEW)
                .sign(PacketType.EVIDENCE_REQUEST, "budget-session", request.toByteArray(), server.getPrivate())
                .toByteArray();

        ClientHandshakeEngine.VerifiedEvidenceRequest verified = client.receiveEvidenceRequest(encodedRequest);
        assertFalse(verified.rawContentRetained());
        assertEquals(0L, verified.retentionSeconds());
        assertTrue(verified.retentionPolicyId().isEmpty());
        assertTrue(verified.retentionPurpose().isEmpty());
        ClientHandshakeEngine.EvidenceConsentGrant consent = client.grantEvidenceConsent(verified);
        assertThrows(EnvelopeException.class, () -> client.grantEvidenceConsent(verified),
                "one signed request must require one fresh visible decision");
        List<ClientHandshakeEngine.OutboundFrame> frames = client.createEvidenceTransferFrames(
                verified, consent, CLOCK.millis(), 2, 2,
                "frame-bytes".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertEquals(3, frames.size());
        EvidenceBegin begin = EvidenceBegin.parseFrom(SignedEnvelope.parseFrom(frames.get(0).data()).getPayload());
        EvidenceChunk chunk = EvidenceChunk.parseFrom(SignedEnvelope.parseFrom(frames.get(1).data()).getPayload());
        EvidenceCommit commit = EvidenceCommit.parseFrom(SignedEnvelope.parseFrom(frames.get(2).data()).getPayload());
        assertEquals("request-1", begin.getRequestId());
        assertEquals(begin.getRequestId(), chunk.getRequestId());
        assertEquals(begin.getRequestId(), commit.getRequestId());
        assertEquals(begin.getPlayerId(), chunk.getPlayerId());
        assertEquals(begin.getPlayerId(), commit.getPlayerId());
        assertEquals(1L, begin.getTransportSequence());
        assertEquals(2L, chunk.getTransportSequence());
        assertEquals(3L, commit.getTransportSequence());
        assertEquals(EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED, begin.getCollectionStatus());
    }

    @Test
    void retentionDisclosureIsVerifiedBeforeConsentAndCannotBeTampered() throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = readyClient(server);
        client.createAuthentication(ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, CLOCK.instant(), List.of(), new byte[32]))));
        client.receiveAuthResult(authResult(server, true));
        EnvelopeCodec codec = new EnvelopeCodec(
                CLOCK, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES, ProtocolConstants.DEFAULT_CLOCK_SKEW);

        EvidenceRequest conflicting = EvidenceRequest.newBuilder()
                .setEvidenceId("retention-conflict")
                .setRequestId("retention-conflict")
                .setPlayerId(clientPlayerId(client))
                .setType(EvidenceType.SCREENSHOT)
                .setCaptureScope(EvidenceCaptureScope.GAME_RENDER_FRAME)
                .setExpiresAtEpochMs(CLOCK.millis() + Duration.ofMinutes(1).toMillis())
                .setRetentionSeconds(1)
                .build();
        assertThrows(EnvelopeException.class, () -> client.receiveEvidenceRequest(codec.sign(
                PacketType.EVIDENCE_REQUEST, "budget-session", conflicting.toByteArray(), server.getPrivate())
                .toByteArray()));

        EvidenceRequest expired = conflicting.toBuilder()
                .setEvidenceId("retention-expired")
                .setRequestId("retention-expired")
                .setRetentionSeconds(0)
                .setExpiresAtEpochMs(CLOCK.millis() - 1)
                .build();
        assertThrows(EnvelopeException.class, () -> client.receiveEvidenceRequest(codec.sign(
                PacketType.EVIDENCE_REQUEST, "budget-session", expired.toByteArray(), server.getPrivate())
                .toByteArray()));

        EvidenceRequest retained = conflicting.toBuilder()
                .setEvidenceId("retention-valid")
                .setRequestId("retention-valid")
                .setRawContentRetained(true)
                .setRetentionSeconds(3600)
                .setRetentionPolicyId("case-review-v1")
                .setRetentionPurpose("review consented game-render evidence")
                .build();
        byte[] retainedFrame = codec.sign(
                PacketType.EVIDENCE_REQUEST, "budget-session", retained.toByteArray(), server.getPrivate())
                .toByteArray();
        SignedEnvelope tampered = SignedEnvelope.parseFrom(retainedFrame).toBuilder()
                .setSignature(ByteString.copyFrom(new byte[64]))
                .build();
        assertThrows(EnvelopeException.class, () -> client.receiveEvidenceRequest(tampered.toByteArray()));

        ClientHandshakeEngine.VerifiedEvidenceRequest verified = client.receiveEvidenceRequest(retainedFrame);
        assertTrue(verified.rawContentRetained());
        assertEquals(3600L, verified.retentionSeconds());
        assertEquals("case-review-v1", verified.retentionPolicyId());
        assertEquals("review consented game-render evidence", verified.retentionPurpose());
        assertTrue(client.grantEvidenceConsent(verified) != null);
    }

    @Test
    void gameWindowScopeReturnsZeroContentUnavailableAndRequestCannotBeReused() throws Exception {
        assertUnsupportedScopeReturnsZeroContent(EvidenceCaptureScope.GAME_WINDOW, "game-window");
    }

    @Test
    void desktopScopeReturnsZeroContentUnavailableAndRequestCannotBeReused() throws Exception {
        assertUnsupportedScopeReturnsZeroContent(EvidenceCaptureScope.DESKTOP, "desktop");
    }

    private void assertUnsupportedScopeReturnsZeroContent(
            EvidenceCaptureScope scope, String suffix) throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = readyClient(server);
        client.createAuthentication(ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, CLOCK.instant(), List.of(), new byte[32]))));
        client.receiveAuthResult(authResult(server, true));
        EvidenceRequest request = EvidenceRequest.newBuilder()
                .setEvidenceId("evidence-" + suffix)
                .setRequestId("request-" + suffix)
                .setPlayerId(clientPlayerId(client))
                .setType(EvidenceType.SCREENSHOT)
                .setCaptureScope(scope)
                .setExpiresAtEpochMs(CLOCK.millis() + Duration.ofMinutes(1).toMillis())
                .build();
        byte[] encodedRequest = new EnvelopeCodec(
                CLOCK, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES, ProtocolConstants.DEFAULT_CLOCK_SKEW)
                .sign(PacketType.EVIDENCE_REQUEST, "budget-session", request.toByteArray(), server.getPrivate())
                .toByteArray();

        ClientHandshakeEngine.VerifiedEvidenceRequest verified = client.receiveEvidenceRequest(encodedRequest);
        assertThrows(EnvelopeException.class, () -> client.grantEvidenceConsent(verified),
                "unsupported scope must never produce a content authorization");
        EvidenceResponse response = EvidenceResponse.parseFrom(SignedEnvelope.parseFrom(
                client.createEvidenceResponseFrames(
                        verified, EvidenceCollectionStatus.EVIDENCE_COLLECTION_UNAVAILABLE).getFirst().data())
                .getPayload());
        assertEquals(EvidenceCollectionStatus.EVIDENCE_COLLECTION_UNAVAILABLE, response.getCollectionStatusCode());
        assertTrue(response.getContent().isEmpty());
        assertTrue(response.getContentSha256().isEmpty());
        assertEquals(scope, response.getCaptureScope());
        assertEquals("request-" + suffix, response.getRequestId());
        assertEquals(clientPlayerId(client), response.getPlayerId());
        client.completeEvidenceRequest(verified);
        assertThrows(EnvelopeException.class, () -> client.createEvidenceResponseFrames(
                verified, EvidenceCollectionStatus.EVIDENCE_COLLECTION_DECLINED));
    }

    @Test
    void acceptsOnlyServerSignedBoundEvidenceCompleteAck() throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = readyClient(server);
        client.createAuthentication(ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, CLOCK.instant(), List.of(), new byte[32]))));
        client.receiveAuthResult(authResult(server, true));
        EvidenceRequest request = EvidenceRequest.newBuilder()
                .setEvidenceId("evidence-ack")
                .setRequestId("request-ack")
                .setPlayerId(clientPlayerId(client))
                .setType(EvidenceType.SCREENSHOT)
                .setCaptureScope(EvidenceCaptureScope.GAME_RENDER_FRAME)
                .setExpiresAtEpochMs(CLOCK.millis() + Duration.ofMinutes(1).toMillis())
                .build();
        byte[] requestFrame = new EnvelopeCodec(
                CLOCK, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES, ProtocolConstants.DEFAULT_CLOCK_SKEW)
                .sign(PacketType.EVIDENCE_REQUEST, "budget-session", request.toByteArray(), server.getPrivate())
                .toByteArray();
        ClientHandshakeEngine.VerifiedEvidenceRequest verified = client.receiveEvidenceRequest(requestFrame);
        ClientHandshakeEngine.EvidenceConsentGrant consent = client.grantEvidenceConsent(verified);
        client.createEvidenceTransferFrames(
                verified, consent, CLOCK.millis(), 2, 2, new byte[] {1, 2, 3});
        EvidenceAck ack = EvidenceAck.newBuilder()
                .setRequestId(request.getRequestId())
                .setEvidenceId(request.getEvidenceId())
                .setAcknowledgedPacketType(PacketType.EVIDENCE_COMMIT)
                .setStatus(EvidenceAckStatus.EVIDENCE_ACK_COMPLETE)
                .setTransportSequence(3)
                .build();
        byte[] ackFrame = new EnvelopeCodec(
                CLOCK, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES, ProtocolConstants.DEFAULT_CLOCK_SKEW)
                .sign(PacketType.EVIDENCE_ACK, "budget-session", ack.toByteArray(), server.getPrivate())
                .toByteArray();

        ClientHandshakeEngine.VerifiedEvidenceAck accepted = client.receiveEvidenceAck(ackFrame);
        assertEquals(verified.requestId(), accepted.request().requestId());
        client.completeEvidenceRequest(verified);
        assertThrows(EnvelopeException.class, () -> client.receiveEvidenceAck(ackFrame));
    }

    @Test
    void rejectsDuplicateAndOutOfOrderServerEvidenceAcknowledgements() throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = readyClient(server);
        client.createAuthentication(ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, CLOCK.instant(), List.of(), new byte[32]))));
        client.receiveAuthResult(authResult(server, true));
        EvidenceRequest request = EvidenceRequest.newBuilder()
                .setEvidenceId("evidence-sequence")
                .setRequestId("request-sequence")
                .setPlayerId(clientPlayerId(client))
                .setType(EvidenceType.SCREENSHOT)
                .setCaptureScope(EvidenceCaptureScope.GAME_RENDER_FRAME)
                .setExpiresAtEpochMs(CLOCK.millis() + Duration.ofMinutes(1).toMillis())
                .build();
        EnvelopeCodec codec = new EnvelopeCodec(
                CLOCK, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES, ProtocolConstants.DEFAULT_CLOCK_SKEW);
        ClientHandshakeEngine.VerifiedEvidenceRequest verified = client.receiveEvidenceRequest(codec.sign(
                PacketType.EVIDENCE_REQUEST, "budget-session", request.toByteArray(), server.getPrivate()).toByteArray());
        client.createEvidenceTransferFrames(
                verified, client.grantEvidenceConsent(verified), CLOCK.millis(), 2, 2, new byte[] {1, 2, 3});

        EvidenceAck accepted = EvidenceAck.newBuilder()
                .setRequestId(request.getRequestId())
                .setEvidenceId(request.getEvidenceId())
                .setAcknowledgedPacketType(PacketType.EVIDENCE_BEGIN)
                .setStatus(EvidenceAckStatus.EVIDENCE_ACK_ACCEPTED)
                .setTransportSequence(1)
                .build();
        byte[] acceptedFrame = codec.sign(
                PacketType.EVIDENCE_ACK, "budget-session", accepted.toByteArray(), server.getPrivate()).toByteArray();
        client.receiveEvidenceAck(acceptedFrame);
        assertThrows(EnvelopeException.class, () -> client.receiveEvidenceAck(acceptedFrame));

        EvidenceAck outOfOrder = accepted.toBuilder()
                .setAcknowledgedPacketType(PacketType.EVIDENCE_COMMIT)
                .setStatus(EvidenceAckStatus.EVIDENCE_ACK_COMPLETE)
                .setTransportSequence(2)
                .build();
        assertThrows(EnvelopeException.class, () -> client.receiveEvidenceAck(codec.sign(
                PacketType.EVIDENCE_ACK, "budget-session", outOfOrder.toByteArray(), server.getPrivate()).toByteArray()));

        EvidenceAck complete = outOfOrder.toBuilder().setTransportSequence(3).build();
        ClientHandshakeEngine.VerifiedEvidenceAck verifiedAck = client.receiveEvidenceAck(codec.sign(
                PacketType.EVIDENCE_ACK, "budget-session", complete.toByteArray(), server.getPrivate()).toByteArray());
        assertEquals(request.getRequestId(), verifiedAck.request().requestId());
    }

    @Test
    void acceptsOnlyServerSignedBoundEvidenceErrorAndCancelsPendingRequest() throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = readyClient(server);
        client.createAuthentication(ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, CLOCK.instant(), List.of(), new byte[32]))));
        client.receiveAuthResult(authResult(server, true));
        EvidenceRequest request = EvidenceRequest.newBuilder()
                .setEvidenceId("evidence-error")
                .setRequestId("request-error")
                .setPlayerId(clientPlayerId(client))
                .setType(EvidenceType.SCREENSHOT)
                .setCaptureScope(EvidenceCaptureScope.GAME_RENDER_FRAME)
                .setExpiresAtEpochMs(CLOCK.millis() + Duration.ofMinutes(1).toMillis())
                .build();
        byte[] requestFrame = new EnvelopeCodec(
                CLOCK, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES, ProtocolConstants.DEFAULT_CLOCK_SKEW)
                .sign(PacketType.EVIDENCE_REQUEST, "budget-session", request.toByteArray(), server.getPrivate())
                .toByteArray();
        ClientHandshakeEngine.VerifiedEvidenceRequest verified = client.receiveEvidenceRequest(requestFrame);
        EvidenceError error = EvidenceError.newBuilder()
                .setRequestId(request.getRequestId())
                .setEvidenceId(request.getEvidenceId())
                .setRejectedPacketType(PacketType.EVIDENCE_CHUNK)
                .setCode(EvidenceErrorCode.EVIDENCE_ERROR_DECLINED)
                .setTransportSequence(2)
                .build();
        byte[] errorFrame = new EnvelopeCodec(
                CLOCK, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES, ProtocolConstants.DEFAULT_CLOCK_SKEW)
                .sign(PacketType.EVIDENCE_ERROR, "budget-session", error.toByteArray(), server.getPrivate())
                .toByteArray();

        ClientHandshakeEngine.VerifiedEvidenceError rejected = client.receiveEvidenceError(errorFrame);
        assertEquals(verified.requestId(), rejected.request().requestId());
        client.cancelEvidenceRequest(verified);
        assertThrows(EnvelopeException.class, () -> client.receiveEvidenceError(errorFrame));
    }

    private static String clientPlayerId(ClientHandshakeEngine client) {
        // The test engine intentionally does not expose player identity. Build requests in the
        // same way as the production client by using the UUID retained by the fixture below.
        return TEST_PLAYER_ID.toString();
    }

    private static final UUID TEST_PLAYER_ID = UUID.fromString("9f2e62d4-13f8-45fb-a6d6-6b1f0b6f71be");

    private static byte[] serverHello(KeyPair server) throws Exception {
        SecurityPolicy policy = SecurityPolicy.newBuilder()
                .setPolicyVersion("budget-policy")
                .setSequence(1)
                .setServerId("budget-server")
                .setIssuedAtEpochMs(CLOCK.millis())
                .setExpiresAtEpochMs(CLOCK.millis() + Duration.ofHours(1).toMillis())
                .setRequiredLevel(TrustLevel.VERIFIED)
                .addAllowedMinecraftVersions("1.21.1")
                .addAllowedLoaders(LoaderType.FABRIC)
                .addAllowedBuildIds("test-build")
                .addIntegrityScopes(IntegrityScopeRule.newBuilder()
                        .setScope("mods")
                        .setRelativeRoot("mods")
                        .setRequired(true)
                        .setMaxEntries(4096)
                        .setMaxFileBytes(1024)
                        .addAllowedExtensions(".jar"))
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(server.getPublic())))
                .build();
        ServerHello hello = ServerHello.newBuilder()
                .setServerId(policy.getServerId())
                .setChallengeNonce(ByteString.copyFrom(new byte[ProtocolConstants.NONCE_BYTES]))
                .setRequiredLevel(TrustLevel.VERIFIED)
                .setPolicyVersion(policy.getPolicyVersion())
                .setSignedPolicy(PolicyDocuments.sign(policy, server.getPrivate(), server.getPublic()))
                .build();
        return new EnvelopeCodec(
                CLOCK, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES, ProtocolConstants.DEFAULT_CLOCK_SKEW)
                .sign(PacketType.SERVER_HELLO, "budget-session", hello.toByteArray(), server.getPrivate())
                .toByteArray();
    }

    private static byte[] authResult(KeyPair server, boolean accepted) throws Exception {
        return authResult(server, accepted, CLOCK, Duration.ofMinutes(2));
    }

    private static byte[] authResult(KeyPair server, boolean accepted, Clock clock, Duration lifetime) throws Exception {
        AuthResult result = AuthResult.newBuilder()
                .setAccepted(accepted)
                .setTrustLevel(accepted ? TrustLevel.VERIFIED : TrustLevel.UNKNOWN)
                .setExpiresAtEpochMs(accepted ? clock.millis() + lifetime.toMillis() : 0)
                .build();
        return new EnvelopeCodec(
                clock, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES, ProtocolConstants.DEFAULT_CLOCK_SKEW)
                .sign(PacketType.AUTH_RESULT, "budget-session", result.toByteArray(), server.getPrivate())
                .toByteArray();
    }

    private ClientHandshakeEngine readyClient(KeyPair server) throws Exception {
        return readyClient(server, CLOCK);
    }

    private ClientHandshakeEngine readyClient(KeyPair server, Clock clock) throws Exception {
        ClientHandshakeEngine client = new ClientHandshakeEngine(
                TEST_PLAYER_ID,
                "test-client",
                "1.21.1",
                "test-build",
                LoaderType.FABRIC,
                server.getPublic(),
                clock,
                new SecureRandom());
        client.prepareServerHello(serverHello(server), "budget.example:25565",
                new VerifiedPolicyCache(temporaryDirectory.resolve(UUID.randomUUID().toString()), clock));
        return client;
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }

    private static ClientIntegrityBundle oversizedBundle() throws Exception {
        String prefix = "x".repeat(300);
        List<IntegrityEntry> entries = java.util.stream.IntStream.range(0, 4096)
                .mapToObj(index -> new IntegrityEntry(prefix + index + ".jar", 1, new byte[32]))
                .toList();
        return ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, CLOCK.instant(), entries, new byte[32])));
    }

    private static ClientIntegrityBundle fragmentedBundle() throws Exception {
        String prefix = "x".repeat(128);
        List<IntegrityEntry> entries = java.util.stream.IntStream.range(0, 512)
                .mapToObj(index -> new IntegrityEntry(prefix + index + ".jar", 1, new byte[32]))
                .toList();
        return ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, CLOCK.instant(), entries, new byte[32])));
    }
}
