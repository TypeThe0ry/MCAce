package com.ellan.mcace.core.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.client.integrity.ClientIntegrityBundle;
import com.ellan.mcace.client.integrity.ScopeIntegrityManifest;
import com.ellan.mcace.client.policy.VerifiedPolicyCache;
import com.ellan.mcace.client.session.ClientHandshakeEngine;
import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.core.persistence.EvidenceMetadataDraft;
import com.ellan.mcace.core.persistence.ObservationOrigin;
import com.ellan.mcace.core.persistence.RiskEventAuditRecord;
import com.ellan.mcace.core.persistence.SecurityAuditSink;
import com.ellan.mcace.core.persistence.SecurityPersistenceException;
import com.ellan.mcace.core.persistence.SessionAuditRecord;
import com.ellan.mcace.core.persistence.StoredEvidenceMetadata;
import com.ellan.mcace.core.risk.RiskEngine;
import com.ellan.mcace.core.risk.RiskPolicy;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.generated.AuthResult;
import com.ellan.mcace.protocol.generated.ClientHello;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.DelegatedSigningKey;
import com.ellan.mcace.protocol.generated.IntegrityScopeRule;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.PolicyTrustStatement;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.ellan.mcace.protocol.integrity.IntegrityDigests;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.RiskBand;
import com.google.protobuf.ByteString;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.ArrayList;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class HandshakeIntegrationTest {
    private MutableClock clock;
    private InMemoryMCAceApi api;
    private KeyPair serverKeys;
    private ServerHandshakeCoordinator server;
    private SignedPolicyDocument signedPolicy;
    private UUID playerId;
    @TempDir
    Path temporaryDirectory;

    @BeforeEach
    void setUp() throws Exception {
        clock = new MutableClock(Instant.parse("2026-08-08T08:00:00Z"));
        api = new InMemoryMCAceApi();
        serverKeys = Ed25519Keys.generate(new SecureRandom());
        KeyPair policyKeys = Ed25519Keys.generate(new SecureRandom());
        SecurityPolicy policy = SecurityPolicy.newBuilder()
                .setPolicyVersion("phase2-test")
                .setSequence(1)
                .setServerId("test-network")
                .setIssuedAtEpochMs(clock.millis())
                .setExpiresAtEpochMs(clock.millis() + Duration.ofHours(1).toMillis())
                .setRequiredLevel(TrustLevel.VERIFIED)
                .addAllowedMinecraftVersions("1.21.1")
                .addAllowedLoaders(LoaderType.FABRIC)
                .addAllowedBuildIds("test-build")
                .addIntegrityScopes(IntegrityScopeRule.newBuilder()
                        .setScope("mods").setRelativeRoot("mods").setRequired(true)
                        .setMaxEntries(16).setMaxFileBytes(1024 * 1024).addAllowedExtensions(".jar"))
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(policyKeys.getPublic())))
                .build();
        var trust = PolicyDocuments.signTrustStatement(PolicyTrustStatement.newBuilder()
                .setSequence(1).setServerId("test-network")
                .setIssuedAtEpochMs(clock.millis())
                .setExpiresAtEpochMs(clock.millis() + Duration.ofDays(30).toMillis())
                .setRootKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(serverKeys.getPublic())))
                .addDelegatedSigningKeys(DelegatedSigningKey.newBuilder()
                        .setKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(policyKeys.getPublic())))
                        .setPublicKeyX509(ByteString.copyFrom(policyKeys.getPublic().getEncoded()))
                        .setNotBeforeEpochMs(clock.millis())
                        .setNotAfterEpochMs(clock.millis() + Duration.ofDays(14).toMillis()))
                .build(), serverKeys.getPrivate(), serverKeys.getPublic());
        signedPolicy = PolicyDocuments.signDelegated(
                policy, policyKeys.getPrivate(), policyKeys.getPublic(), trust);
        server = new ServerHandshakeCoordinator(
                clock,
                new SecureRandom(),
                serverKeys,
                new RiskEngine(RiskPolicy.defaults()),
                api,
                Duration.ofSeconds(5),
                () -> signedPolicy);
        playerId = UUID.randomUUID();
    }

    @Test
    void completesPinnedChallengeResponseFlow() throws Exception {
        ClientHandshakeEngine client = client(serverKeys);
        assertTrue(server.federationSubject(playerId).isEmpty());
        byte[] serverHello = server.begin(playerId);
        List<byte[]> clientFrames = frames(client, serverHello);

        HandshakeAction helloAction = server.receive(playerId, clientFrames.get(0));
        HandshakeAction authAction = server.receive(playerId, clientFrames.get(1));
        AuthResult result = client.receiveAuthResult(authAction.outboundFrames().getFirst());

        assertTrue(helloAction.outboundFrames().isEmpty());
        assertFalse(helloAction.protocolViolation());
        assertTrue(result.getAccepted());
        assertEquals(TrustLevel.VERIFIED, result.getTrustLevel());
        assertEquals(AdmissionStatus.VERIFIED, authAction.snapshot().orElseThrow().admissionStatus());
        assertTrue(api.isVerified(playerId));
        String currentSessionId = server.currentAuthenticatedSessionId(playerId).orElseThrow();
        assertTrue(server.isCurrentAuthenticatedSession(playerId, currentSessionId));
        com.ellan.mcace.core.federation.FederationSubject federation =
                server.federationSubject(playerId).orElseThrow();
        assertEquals("test-network", federation.localNetworkId());
        assertEquals("phase2-test", federation.policyVersion());
        assertEquals(ProtocolConstants.NONCE_BYTES, federation.serverChallengeNonce().length);
        assertEquals(32, federation.policySha256().length);
        server.remove(playerId);
        assertTrue(server.currentAuthenticatedSessionId(playerId).isEmpty());
        assertTrue(server.federationSubject(playerId).isEmpty());
    }

    @Test
    void acceptsBoundedPostAuthObservationWithoutChangingVerifiedAdmissionAndIgnoresReplay() throws Exception {
        AtomicInteger updates = new AtomicInteger();
        server = new ServerHandshakeCoordinator(
                clock, new SecureRandom(), serverKeys, new RiskEngine(RiskPolicy.defaults()), api,
                Duration.ofSeconds(5), () -> signedPolicy,
                com.ellan.mcace.core.persistence.SecurityAuditSink.noop(), ignored -> { }, ignored -> { },
                ignored -> updates.incrementAndGet(),
                com.ellan.mcace.core.evidence.EvidenceContentStore.discard(),
                com.ellan.mcace.core.evidence.EvidenceAuditSink.noop());
        ClientHandshakeEngine client = client(serverKeys);
        byte[] hello = server.begin(playerId);
        client.prepareServerHello(hello, "test.example:25565",
                new VerifiedPolicyCache(temporaryDirectory.resolve("dynamic-update"), clock));
        ClientIntegrityBundle bundle = emptyBundle();
        List<byte[]> authentication = client.createAuthentication(bundle);
        server.receive(playerId, authentication.get(0));
        HandshakeAction authenticated = server.receive(playerId, authentication.get(1));
        client.receiveAuthResult(authenticated.outboundFrames().getFirst());
        ClientHandshakeEngine.PreparedArtifactObservationUpdate update =
                client.prepareArtifactObservationUpdate(bundle, List.of());
        // Preparing frames is not a state transition: a failed platform send can be replaced by
        // a fresh preparation with the same first update sequence.
        ClientHandshakeEngine.PreparedArtifactObservationUpdate replacement =
                client.prepareArtifactObservationUpdate(bundle, List.of());
        for (ClientHandshakeEngine.OutboundFrame frame : replacement.frames()) server.receive(playerId, frame.data());
        client.commitArtifactObservationUpdate(replacement);
        assertThrows(EnvelopeException.class, () -> client.commitArtifactObservationUpdate(update));

        assertEquals(1, updates.get());
        assertTrue(api.snapshot(playerId).orElseThrow().verified());
        assertEquals(AdmissionStatus.VERIFIED, api.snapshot(playerId).orElseThrow().admissionStatus());
        for (ClientHandshakeEngine.OutboundFrame frame : replacement.frames()) server.receive(playerId, frame.data());
        assertEquals(1, updates.get());
        assertTrue(api.snapshot(playerId).orElseThrow().verified());
    }

    @Test
    void optionalMissingHeartbeatControlIsConsecutiveReversibleAndDoesNotChangeAdmission() throws Exception {
        ClientHandshakeEngine client = client(serverKeys);
        List<byte[]> frames = frames(client, server.begin(playerId));
        server.receive(playerId, frames.getFirst());
        HandshakeAction authenticated = server.receive(playerId, frames.get(1));
        client.receiveAuthResult(authenticated.outboundFrames().getFirst());
        HeartbeatMissingPolicy policy = new HeartbeatMissingPolicy(true, 2, HeartbeatMissingPolicy.Action.NOTICE);
        byte[] firstHeartbeat = client.createHeartbeat();
        assertTrue(!server.receive(playerId, firstHeartbeat).protocolViolation());
        clock.advance(Duration.ofSeconds(61));
        assertTrue(server.pollHeartbeatMissingTransitions(policy).isEmpty());
        assertTrue(server.pollHeartbeatMissingTransitions(policy).isEmpty());
        clock.advance(Duration.ofSeconds(30));
        assertTrue(server.pollHeartbeatMissingTransitions(policy).isEmpty());
        HeartbeatMissingTransition applied = server.pollHeartbeatMissingTransitions(policy).getFirst();
        assertEquals(HeartbeatMissingTransition.Kind.APPLY, applied.kind());
        assertEquals(HeartbeatMissingPolicy.Action.NOTICE, applied.action());
        assertTrue(api.snapshot(playerId).orElseThrow().verified());
        assertEquals(AdmissionStatus.VERIFIED, api.snapshot(playerId).orElseThrow().admissionStatus());

        assertTrue(server.receive(playerId, firstHeartbeat).protocolViolation());
        assertTrue(server.pollHeartbeatMissingTransitions(policy).isEmpty());
        server.receive(playerId, client.createHeartbeat());
        HeartbeatMissingTransition recovered = server.pollHeartbeatMissingTransitions(policy).getFirst();
        assertEquals(HeartbeatMissingTransition.Kind.RECOVER, recovered.kind());
        assertTrue(api.snapshot(playerId).orElseThrow().verified());
        assertTrue(server.pollHeartbeatMissingTransitions(HeartbeatMissingPolicy.disabled()).isEmpty());
    }

    @Test
    void rejectsReplayedClientFrameWithoutCreatingBan() throws Exception {
        ClientHandshakeEngine client = client(serverKeys);
        List<byte[]> frames = frames(client, server.begin(playerId));

        server.receive(playerId, frames.getFirst());
        HandshakeAction replay = server.receive(playerId, frames.getFirst());

        assertTrue(replay.protocolViolation());
        assertEquals(RiskBand.INVESTIGATION, replay.snapshot().orElseThrow().riskBand());
        assertEquals(AdmissionStatus.LIMITED, replay.snapshot().orElseThrow().admissionStatus());
        assertFalse(api.isVerified(playerId));
    }

    @Test
    void degradesMissingClientAfterTimeout() throws Exception {
        server.begin(playerId);
        clock.advance(Duration.ofSeconds(6));

        List<com.ellan.mcace.sdk.PlayerSecuritySnapshot> expired = server.expireTimedOut();

        assertEquals(1, expired.size());
        assertEquals(20, expired.getFirst().riskScore());
        assertEquals(AdmissionStatus.LIMITED, expired.getFirst().admissionStatus());
        assertEquals(TrustLevel.UNKNOWN, expired.getFirst().trustLevel());
    }

    @Test
    void rejectsUnpinnedServerIdentity() throws Exception {
        KeyPair unrelatedServer = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = client(unrelatedServer);
        byte[] serverHello = server.begin(playerId);

        assertThrows(EnvelopeException.class, () -> frames(client, serverHello));
    }

    @Test
    void rejectsAuthenticationBeforeClientIdentification() throws Exception {
        ClientHandshakeEngine client = client(serverKeys);
        List<byte[]> frames = frames(client, server.begin(playerId));

        HandshakeAction outOfOrder = server.receive(playerId, frames.get(1));

        assertTrue(outOfOrder.protocolViolation());
        assertEquals(AdmissionStatus.LIMITED, outOfOrder.snapshot().orElseThrow().admissionStatus());
        assertFalse(api.isVerified(playerId));
    }

    @Test
    void rejectsForgedClientSignature() throws Exception {
        ClientHandshakeEngine client = client(serverKeys);
        List<byte[]> frames = frames(client, server.begin(playerId));
        SignedEnvelope original = SignedEnvelope.parseFrom(frames.getFirst());
        byte[] signature = original.getSignature().toByteArray();
        signature[0] ^= 0x01;
        byte[] forged = original.toBuilder().setSignature(ByteString.copyFrom(signature)).build().toByteArray();

        HandshakeAction action = server.receive(playerId, forged);

        assertTrue(action.protocolViolation());
        assertEquals(RiskBand.INVESTIGATION, action.snapshot().orElseThrow().riskBand());
    }

    @Test
    void rejectsValidSignatureWithWrongChallenge() throws Exception {
        byte[] encodedServerHello = server.begin(playerId);
        SignedEnvelope serverEnvelope = SignedEnvelope.parseFrom(encodedServerHello);
        KeyPair attackerKeys = Ed25519Keys.generate(new SecureRandom());
        byte[] wrongChallenge = new byte[32];
        java.util.Arrays.fill(wrongChallenge, (byte) 0x7f);
        ClientHello wrongHello = ClientHello.newBuilder()
                .setClientVersion("0.1.0-SNAPSHOT")
                .setLoader(LoaderType.FABRIC)
                .setMinecraftVersion("1.21.1")
                .setPublicKeyX509(ByteString.copyFrom(attackerKeys.getPublic().getEncoded()))
                .setBuildId("attacker-build")
                .setChallengeNonce(ByteString.copyFrom(wrongChallenge))
                .build();
        EnvelopeCodec codec = new EnvelopeCodec(clock, new SecureRandom(), 1024 * 1024, Duration.ofSeconds(30));
        byte[] wrongFrame = codec.sign(
                PacketType.CLIENT_HELLO,
                serverEnvelope.getHeader().getSessionId(),
                wrongHello.toByteArray(),
                attackerKeys.getPrivate()).toByteArray();

        HandshakeAction action = server.receive(playerId, wrongFrame);

        assertTrue(action.protocolViolation());
        assertEquals(AdmissionStatus.LIMITED, action.snapshot().orElseThrow().admissionStatus());
    }

    @Test
    void heartbeatTransitionsAreMonitorOnlyAndRecoverAfterAProlongedGap() throws Exception {
        ClientHandshakeEngine client = client(serverKeys);
        List<byte[]> frames = frames(client, server.begin(playerId));
        server.receive(playerId, frames.getFirst());
        HandshakeAction authenticated = server.receive(playerId, frames.get(1));
        client.receiveAuthResult(authenticated.outboundFrames().getFirst());

        byte[] first = client.createHeartbeat();
        assertFalse(server.receive(playerId, first).protocolViolation());
        // Current and future protocol implementations may represent first-packet grace
        // differently; clear any initial observation without treating it as a degradation.
        server.pollHeartbeatTransitions();

        clock.advance(ProtocolConstants.HEARTBEAT_INTERVAL.plusSeconds(1));
        assertTrue(server.pollHeartbeatTransitions().isEmpty(), "a single missed interval stays active");

        clock.advance(ProtocolConstants.HEARTBEAT_INTERVAL.plusSeconds(1));
        List<HeartbeatTransition> stale = server.pollHeartbeatTransitions();
        assertEquals(1, stale.size());
        assertEquals(com.ellan.mcace.protocol.heartbeat.HeartbeatHealth.STALE, stale.getFirst().current());
        assertTrue(api.isVerified(playerId));
        assertEquals(AdmissionStatus.VERIFIED, api.snapshot(playerId).orElseThrow().admissionStatus());

        clock.advance(ProtocolConstants.HEARTBEAT_INTERVAL.plusSeconds(1));
        List<HeartbeatTransition> missing = server.pollHeartbeatTransitions();
        assertEquals(1, missing.size());
        assertEquals(com.ellan.mcace.protocol.heartbeat.HeartbeatHealth.MISSING, missing.getFirst().current());
        assertTrue(api.isVerified(playerId));

        assertFalse(server.receive(playerId, client.createHeartbeat()).protocolViolation());
        List<HeartbeatTransition> recovered = server.pollHeartbeatTransitions();
        assertEquals(1, recovered.size());
        assertEquals(com.ellan.mcace.protocol.heartbeat.HeartbeatHealth.ACTIVE, recovered.getFirst().current());
        assertTrue(api.isVerified(playerId));
    }

    @Test
    void longHeartbeatSessionOutlivesTwoMinuteAuthResultFreshness() throws Exception {
        ClientHandshakeEngine client = client(serverKeys);
        List<byte[]> frames = frames(client, server.begin(playerId));
        server.receive(playerId, frames.getFirst());
        HandshakeAction authenticated = server.receive(playerId, frames.get(1));
        AuthResult result = client.receiveAuthResult(authenticated.outboundFrames().getFirst());
        assertEquals(clock.instant().plus(ProtocolConstants.AUTH_RESULT_TTL),
                Instant.ofEpochMilli(result.getExpiresAtEpochMs()));

        for (int tick = 0; tick < 8; tick++) {
            clock.advance(ProtocolConstants.HEARTBEAT_INTERVAL);
            assertFalse(server.receive(playerId, client.createHeartbeat()).protocolViolation());
            assertTrue(server.pollHeartbeatTransitions().isEmpty(),
                    "regular heartbeats must keep a long session ACTIVE after AuthResult TTL");
            assertTrue(api.isVerified(playerId));
            assertEquals(AdmissionStatus.VERIFIED, api.snapshot(playerId).orElseThrow().admissionStatus());
        }
        assertTrue(clock.instant().isAfter(Instant.ofEpochMilli(result.getExpiresAtEpochMs())));
    }

    @Test
    void heartbeatReplayOrSessionMismatchNeverDowngradesVerifiedAdmission() throws Exception {
        ClientHandshakeEngine client = client(serverKeys);
        List<byte[]> frames = frames(client, server.begin(playerId));
        server.receive(playerId, frames.getFirst());
        HandshakeAction authenticated = server.receive(playerId, frames.get(1));
        client.receiveAuthResult(authenticated.outboundFrames().getFirst());

        byte[] heartbeat = client.createHeartbeat();
        assertFalse(server.receive(playerId, heartbeat).protocolViolation());
        assertTrue(server.receive(playerId, heartbeat).protocolViolation(), "replayed nonce must be rejected");
        SignedEnvelope wrongSession = SignedEnvelope.parseFrom(heartbeat).toBuilder()
                .setHeader(SignedEnvelope.parseFrom(heartbeat).getHeader().toBuilder().setSessionId("other-session"))
                .build();
        assertTrue(server.receive(playerId, wrongSession.toByteArray()).protocolViolation(),
                "a session binding mismatch must be rejected");
        assertTrue(api.isVerified(playerId));
        assertEquals(AdmissionStatus.VERIFIED, api.snapshot(playerId).orElseThrow().admissionStatus());
    }

    @Test
    void recordsMissingTelemetryWithExplicitOrigin() throws Exception {
        RecordingAuditSink audit = new RecordingAuditSink();
        server = auditedServer(audit, ignored -> { });

        server.begin(playerId);
        clock.advance(Duration.ofSeconds(6));
        server.expireTimedOut();

        assertEquals(SessionStage.EXPIRED, audit.sessions.getLast().stage());
        assertEquals(ObservationOrigin.MISSING, audit.events.getFirst().origin());
        assertEquals(playerId, audit.events.getFirst().playerId());
    }

    @Test
    void persistenceFailureNeverChangesSuccessfulAdmission() throws Exception {
        AtomicInteger failures = new AtomicInteger();
        SecurityAuditSink failing = new RecordingAuditSink() {
            @Override public void upsertSession(SessionAuditRecord session) throws SecurityPersistenceException {
                throw new SecurityPersistenceException("controlled database failure");
            }
        };
        server = auditedServer(failing, ignored -> failures.incrementAndGet());
        ClientHandshakeEngine client = client(serverKeys);
        List<byte[]> clientFrames = frames(client, server.begin(playerId));

        server.receive(playerId, clientFrames.getFirst());
        HandshakeAction authenticated = server.receive(playerId, clientFrames.get(1));

        assertEquals(AdmissionStatus.VERIFIED, authenticated.snapshot().orElseThrow().admissionStatus());
        assertTrue(failures.get() >= 2);
    }

    @Test
    void oversizedServerHelloDoesNotLeaveAHandshakeOrSnapshot() throws Exception {
        SecurityPolicy.Builder oversized = SecurityPolicy.newBuilder()
                .setPolicyVersion("oversized-test")
                .setSequence(1)
                .setServerId("test-network")
                .setIssuedAtEpochMs(clock.millis())
                .setExpiresAtEpochMs(clock.millis() + Duration.ofHours(1).toMillis())
                .setRequiredLevel(TrustLevel.VERIFIED)
                .addAllowedMinecraftVersions("1.21.1")
                .addAllowedLoaders(LoaderType.FABRIC)
                .addIntegrityScopes(IntegrityScopeRule.newBuilder()
                        .setScope("mods").setRelativeRoot("mods").setRequired(true)
                        .setMaxEntries(16).setMaxFileBytes(1024 * 1024).addAllowedExtensions(".jar"))
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(serverKeys.getPublic())));
        for (int index = 0; index < 1_000; index++) {
            oversized.addAllowedBuildIds("oversized-build-" + index + "-" + "x".repeat(48));
        }
        AtomicReference<SignedPolicyDocument> policy = new AtomicReference<>(PolicyDocuments.sign(
                oversized.build(), serverKeys.getPrivate(), serverKeys.getPublic()));
        server = new ServerHandshakeCoordinator(
                clock,
                new SecureRandom(),
                serverKeys,
                new RiskEngine(RiskPolicy.defaults()),
                api,
                Duration.ofSeconds(5),
                policy::get);

        assertThrows(EnvelopeException.class, () -> server.begin(playerId));
        assertTrue(api.snapshot(playerId).isEmpty());

        policy.set(signedPolicy);
        UUID nextPlayer = UUID.randomUUID();
        assertTrue(server.begin(nextPlayer).length > 0);
        assertEquals(AdmissionStatus.VERIFYING, api.snapshot(nextPlayer).orElseThrow().admissionStatus());
    }

    @Test
    void oversizedRawFrameIsRejectedBeforeParseWithoutChangingAuthenticatedState() throws Exception {
        ClientHandshakeEngine client = client(serverKeys);
        List<byte[]> frames = frames(client, server.begin(playerId));
        server.receive(playerId, frames.getFirst());
        HandshakeAction authenticated = server.receive(playerId, frames.get(1));
        client.receiveAuthResult(authenticated.outboundFrames().getFirst());

        byte[] oversizedPayload = new byte[ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES];
        byte[] oversizedHeartbeat = SignedEnvelope.newBuilder()
                .setHeader(com.ellan.mcace.protocol.generated.EnvelopeHeader.newBuilder()
                        .setPacketType(PacketType.HEARTBEAT).setSessionId("unknown"))
                .setPayload(ByteString.copyFrom(oversizedPayload)).build().toByteArray();
        byte[] oversizedUnknown = SignedEnvelope.newBuilder()
                .setHeader(com.ellan.mcace.protocol.generated.EnvelopeHeader.newBuilder()
                        .setPacketType(PacketType.PACKET_TYPE_UNSPECIFIED).setSessionId("unknown"))
                .setPayload(ByteString.copyFrom(oversizedPayload)).build().toByteArray();
        assertTrue(oversizedHeartbeat.length > ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES);
        assertTrue(oversizedUnknown.length > ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES);
        assertTrue(server.receive(playerId, oversizedHeartbeat).protocolViolation());
        assertTrue(server.receive(playerId, oversizedUnknown).protocolViolation());
        assertTrue(api.isVerified(playerId));
        assertEquals(AdmissionStatus.VERIFIED, api.snapshot(playerId).orElseThrow().admissionStatus());
    }

    private ServerHandshakeCoordinator auditedServer(
            SecurityAuditSink sink,
            java.util.function.Consumer<Exception> failures) throws EnvelopeException {
        return new ServerHandshakeCoordinator(
                clock, new SecureRandom(), serverKeys, new RiskEngine(RiskPolicy.defaults()), api,
                Duration.ofSeconds(5), () -> signedPolicy, sink, failures);
    }

    private ClientHandshakeEngine client(KeyPair pinnedServer) throws EnvelopeException {
        return new ClientHandshakeEngine(
                playerId,
                "0.1.0-SNAPSHOT",
                "1.21.1",
                "test-build",
                LoaderType.FABRIC,
                pinnedServer.getPublic(),
                clock,
                new SecureRandom());
    }

    private List<byte[]> frames(ClientHandshakeEngine client, byte[] hello) throws Exception {
        client.prepareServerHello(hello, "test.example:25565",
                new VerifiedPolicyCache(temporaryDirectory.resolve(UUID.randomUUID().toString()), clock));
        return client.createAuthentication(emptyBundle());
    }

    private ClientIntegrityBundle emptyBundle() throws Exception {
        return ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, clock.instant(), List.of(), IntegrityDigests.scopeRoot(List.of()))));
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        private void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) {
                throw new IllegalArgumentException("test clock only supports UTC");
            }
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }

    private static class RecordingAuditSink implements SecurityAuditSink {
        private final List<SessionAuditRecord> sessions = new ArrayList<>();
        private final List<RiskEventAuditRecord> events = new ArrayList<>();

        @Override public void upsertSession(SessionAuditRecord session) throws SecurityPersistenceException {
            sessions.add(session);
        }

        @Override public void appendRiskEvent(RiskEventAuditRecord event) throws SecurityPersistenceException {
            events.add(event);
        }

        @Override public StoredEvidenceMetadata appendEvidence(EvidenceMetadataDraft evidence) {
            throw new UnsupportedOperationException();
        }
    }
}
