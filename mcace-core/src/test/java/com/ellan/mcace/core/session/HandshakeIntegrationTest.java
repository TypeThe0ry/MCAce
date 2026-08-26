package com.ellan.mcace.core.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.client.integrity.ClientIntegrityBundle;
import com.ellan.mcace.client.integrity.IntegrityEntry;
import com.ellan.mcace.client.integrity.ScopeIntegrityManifest;
import com.ellan.mcace.client.observation.LoadedModObservation;
import com.ellan.mcace.client.policy.VerifiedPolicyCache;
import com.ellan.mcace.client.session.ClientHandshakeEngine;
import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.core.federation.FederationAuthenticationBinding;
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
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.AuthResult;
import com.ellan.mcace.protocol.generated.AuthRequest;
import com.ellan.mcace.protocol.generated.ArtifactObservationResult;
import com.ellan.mcace.protocol.generated.ArtifactObservationResultReason;
import com.ellan.mcace.protocol.generated.ArtifactObservationUpdate;
import com.ellan.mcace.protocol.generated.BoundedPayloadKind;
import com.ellan.mcace.protocol.generated.ClientHello;
import com.ellan.mcace.protocol.generated.ClientCapability;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.LoadedModEntry;
import com.ellan.mcace.protocol.generated.LoadedModOriginKind;
import com.ellan.mcace.protocol.generated.ModEntry;
import com.ellan.mcace.protocol.generated.DelegatedSigningKey;
import com.ellan.mcace.protocol.generated.IntegrityScopeRule;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.generated.ServerHello;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.PolicyTrustStatement;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.ellan.mcace.protocol.integrity.IntegrityDigests;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.transport.BoundedPayloadTransferReceiver;
import com.ellan.mcace.protocol.transport.BoundedPayloadTransferSender;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.RiskBand;
import com.google.protobuf.ByteString;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
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
    private static final String PRODUCT_VERSION_PROPERTY = "mcace.test.product-version";

    private static String productVersion() {
        return System.getProperty(PRODUCT_VERSION_PROPERTY, "0.1.0-SNAPSHOT");
    }

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
        assertTrue(result.getFederationSignedAssertionSha256().isEmpty());
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
        assertTrue(federation.targetAuthenticationBinding().isEmpty());
        server.remove(playerId);
        assertTrue(server.currentAuthenticatedSessionId(playerId).isEmpty());
        assertTrue(server.federationSubject(playerId).isEmpty());
    }

    @Test
    void federationBindingRoundTripsThroughDeferredAuthAndSubject() throws Exception {
        byte[] binding = new byte[32];
        java.util.Arrays.fill(binding, (byte) 0x42);
        KeyPair clientKeys = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = new ClientHandshakeEngine(
                playerId, productVersion(), "1.21.1", "test-build", LoaderType.FABRIC,
                serverKeys.getPublic(), clock, new SecureRandom(), clientKeys, binding);
        List<byte[]> frames = frames(client, server.begin(playerId));
        ClientHello hello = ClientHello.parseFrom(SignedEnvelope.parseFrom(frames.getFirst()).getPayload());
        AuthRequest request = AuthRequest.parseFrom(SignedEnvelope.parseFrom(frames.get(1)).getPayload());
        assertArrayEquals(binding, hello.getFederationSignedAssertionSha256().toByteArray());
        assertArrayEquals(binding, request.getFederationSignedAssertionSha256().toByteArray());

        HandshakeAction deferred = server.receive(playerId, frames.get(1));
        HandshakeAction completed = server.receive(playerId, frames.getFirst());
        assertFalse(deferred.protocolViolation());
        AuthResult result = client.receiveAuthResult(completed.outboundFrames().getFirst());
        assertArrayEquals(binding, result.getFederationSignedAssertionSha256().toByteArray());
        FederationAuthenticationBinding subjectBinding = server.federationSubject(playerId)
                .orElseThrow().targetAuthenticationBinding().orElseThrow();
        assertArrayEquals(binding, subjectBinding.signedAssertionSha256());
    }

    @Test
    void rejectsHalfBoundMismatchedAndOversizedFederationAuthTranscripts() throws Exception {
        byte[] first = new byte[32];
        byte[] second = new byte[32];
        first[0] = 1;
        second[0] = 2;

        assertBindingTranscriptRejected(first, new byte[0]);
        assertBindingTranscriptRejected(new byte[0], first);
        assertBindingTranscriptRejected(first, second);
        assertBindingTranscriptRejected(first, new byte[33]);
        assertHelloBindingRejected(new byte[31]);
        assertHelloBindingRejected(new byte[33]);
    }

    @Test
    void rejectsForgedLoadedModManifestMatchBeforeAuthentication() throws Exception {
        KeyPair clientKeys = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = new ClientHandshakeEngine(
                playerId, productVersion(), "1.21.1", "test-build", LoaderType.FABRIC,
                serverKeys.getPublic(), clock, new SecureRandom(), clientKeys);
        List<byte[]> original = frames(client, server.begin(playerId));
        AuthRequest forged = AuthRequest.parseFrom(
                SignedEnvelope.parseFrom(original.get(1)).getPayload()).toBuilder()
                .addLoadedMods(LoadedModEntry.newBuilder()
                        .setId("forged.mod").setVersion("1")
                        .setOriginKind(LoadedModOriginKind.LOADED_MOD_ORIGIN_MODS_FILE)
                        .setOriginFilename("missing.jar")
                        .setOriginFileSize(99)
                        .setOriginSha256(ByteString.copyFrom(new byte[32]))
                        .setOriginManifestMatched(true))
                .build();

        assertFalse(server.receive(playerId, original.getFirst()).protocolViolation());
        assertTrue(server.receive(playerId, resign(original.get(1), PacketType.AUTH_REQUEST,
                forged.toByteArray(), clientKeys)).protocolViolation());
        assertFalse(api.isVerified(playerId));
    }

    @Test
    void rejectsSelfConsistentExtraModEntryOutsideTheSignedModsScope() throws Exception {
        byte[] realHash = new byte[32];
        realHash[0] = 7;
        ClientIntegrityBundle bundle = bundleWithMod("real.jar", 41L, realHash);
        KeyPair clientKeys = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = new ClientHandshakeEngine(
                playerId, productVersion(), "1.21.1", "test-build", LoaderType.FABRIC,
                serverKeys.getPublic(), clock, new SecureRandom(), clientKeys);
        byte[] serverHello = server.begin(playerId);
        client.prepareServerHello(serverHello, "test.example:25565",
                new VerifiedPolicyCache(temporaryDirectory.resolve("forged-extra-mod"), clock));
        List<ClientHandshakeEngine.OutboundFrame> original =
                client.createAuthenticationFrames(bundle, List.of());
        byte[] forgedHash = new byte[32];
        forgedHash[0] = 11;
        AuthRequest forged = AuthRequest.parseFrom(
                SignedEnvelope.parseFrom(original.get(1).data()).getPayload()).toBuilder()
                .addMods(ModEntry.newBuilder()
                        .setId("meteor-client").setVersion("1")
                        .setFilename("fake.jar").setFileSize(99L)
                        .setSha256(ByteString.copyFrom(forgedHash)))
                .addLoadedMods(LoadedModEntry.newBuilder()
                        .setId("meteor-client").setVersion("1")
                        .setOriginKind(LoadedModOriginKind.LOADED_MOD_ORIGIN_MODS_FILE)
                        .setOriginFilename("fake.jar").setOriginFileSize(99L)
                        .setOriginSha256(ByteString.copyFrom(forgedHash))
                        .setOriginManifestMatched(true))
                .addClientCapabilities(ClientCapability.CLIENT_CAPABILITY_LOADED_MOD_GRAPH_V1)
                .build();

        assertFalse(server.receive(playerId, original.getFirst().data()).protocolViolation());
        assertTrue(server.receive(playerId, resign(original.get(1).data(), PacketType.AUTH_REQUEST,
                forged.toByteArray(), clientKeys)).protocolViolation());
        assertFalse(api.isVerified(playerId));
    }

    @Test
    void rejectsManifestRootThatDoesNotEqualTheSignedModsScopeRoot() throws Exception {
        KeyPair clientKeys = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = new ClientHandshakeEngine(
                playerId, productVersion(), "1.21.1", "test-build", LoaderType.FABRIC,
                serverKeys.getPublic(), clock, new SecureRandom(), clientKeys);
        List<byte[]> original = frames(client, server.begin(playerId));
        byte[] wrongRoot = new byte[32];
        wrongRoot[0] = 1;
        AuthRequest forged = AuthRequest.parseFrom(
                SignedEnvelope.parseFrom(original.get(1)).getPayload()).toBuilder()
                .setManifestRootSha256(ByteString.copyFrom(wrongRoot))
                .build();

        assertFalse(server.receive(playerId, original.getFirst()).protocolViolation());
        assertTrue(server.receive(playerId, resign(original.get(1), PacketType.AUTH_REQUEST,
                forged.toByteArray(), clientKeys)).protocolViolation());
        assertFalse(api.isVerified(playerId));
    }

    @Test
    void signedPolicyCanRequireLoadedGraphCapabilityAndRejectLegacyEmptyRequests() throws Exception {
        SignedPolicyDocument requiredPolicy = signedPolicyRequiringLoadedGraph();
        server = new ServerHandshakeCoordinator(
                clock, new SecureRandom(), serverKeys, new RiskEngine(RiskPolicy.defaults()), api,
                Duration.ofSeconds(5), () -> requiredPolicy);
        KeyPair clientKeys = Ed25519Keys.generate(new SecureRandom());
        byte[] helloFrame = server.begin(playerId);
        SignedEnvelope helloEnvelope = SignedEnvelope.parseFrom(helloFrame);
        ServerHello hello = ServerHello.parseFrom(helloEnvelope.getPayload());
        ClientHello clientHello = ClientHello.newBuilder()
                .setClientVersion(productVersion())
                .setLoader(LoaderType.FABRIC)
                .setMinecraftVersion("1.21.1")
                .setPublicKeyX509(ByteString.copyFrom(clientKeys.getPublic().getEncoded()))
                .setBuildId("test-build")
                .setChallengeNonce(hello.getChallengeNonce())
                .build();
        byte[] emptyRoot = IntegrityDigests.scopeRoot(List.of());
        AuthRequest legacy = AuthRequest.newBuilder()
                .setPlayerUuid(playerId.toString())
                .setClientId("legacy-client")
                .setBuildId("test-build")
                .setManifestRootSha256(ByteString.copyFrom(emptyRoot))
                .setEnvironmentSha256(ByteString.copyFrom(new byte[32]))
                .setPolicySha256(ByteString.copyFrom(PolicyDocuments.policyDigest(requiredPolicy)))
                .setPolicySequence(1L)
                .addScopeManifests(com.ellan.mcace.protocol.generated.IntegrityScopeManifest.newBuilder()
                        .setScope("mods").setRelativeRoot("mods").setPresent(true)
                        .setEntryCount(0).setRootSha256(ByteString.copyFrom(emptyRoot)))
                .build();
        EnvelopeCodec codec = new EnvelopeCodec(clock, new SecureRandom(),
                ProtocolConstants.MAX_PAYLOAD_BYTES, ProtocolConstants.DEFAULT_CLOCK_SKEW);
        String sessionId = helloEnvelope.getHeader().getSessionId();

        assertFalse(server.receive(playerId, codec.sign(PacketType.CLIENT_HELLO, sessionId,
                clientHello.toByteArray(), clientKeys.getPrivate()).toByteArray()).protocolViolation());
        assertTrue(server.receive(playerId, codec.sign(PacketType.AUTH_REQUEST, sessionId,
                legacy.toByteArray(), clientKeys.getPrivate()).toByteArray()).protocolViolation());
        assertFalse(api.isVerified(playerId));
    }

    @Test
    void acceptsCanonicalRuntimeLoadedModGraphAsSignedClientTelemetry() throws Exception {
        ClientHandshakeEngine client = client(serverKeys);
        client.prepareServerHello(server.begin(playerId), "test.example:25565",
                new VerifiedPolicyCache(temporaryDirectory.resolve("loaded-mod-graph"), clock));
        LoadedModObservation fabric = new LoadedModObservation("fabricloader", "0.19.3",
                LoadedModObservation.OriginKind.BUILTIN_OR_CLASSPATH, "", "");
        List<ClientHandshakeEngine.OutboundFrame> frames = client.createAuthenticationFrames(
                emptyBundle(), List.of(), List.of(), List.of(), List.of(fabric));

        assertFalse(server.receive(playerId, frames.getFirst().data()).protocolViolation());
        HandshakeAction authenticated = server.receive(playerId, frames.get(1).data());

        assertFalse(authenticated.protocolViolation());
        assertTrue(api.isVerified(playerId));
        AuthRequest request = AuthRequest.parseFrom(
                SignedEnvelope.parseFrom(frames.get(1).data()).getPayload());
        assertEquals(List.of(ClientCapability.CLIENT_CAPABILITY_LOADED_MOD_GRAPH_V1),
                request.getClientCapabilitiesList());
    }

    @Test
    void rejectsLoadedGraphCapabilityShapeMismatchesAndUnknownValues() throws Exception {
        assertLoadedGraphRequestMutationRejected(
                "missing-capability", builder -> builder.clearClientCapabilities());
        assertLoadedGraphRequestMutationRejected(
                "capability-without-graph", builder -> builder.clearLoadedMods());
        assertLoadedGraphRequestMutationRejected(
                "duplicate-capability", builder -> builder.addClientCapabilities(
                        ClientCapability.CLIENT_CAPABILITY_LOADED_MOD_GRAPH_V1));
        assertLoadedGraphRequestMutationRejected(
                "unspecified-capability", builder -> builder.clearClientCapabilities()
                        .addClientCapabilities(ClientCapability.CLIENT_CAPABILITY_UNSPECIFIED));
        assertLoadedGraphRequestMutationRejected(
                "unknown-capability", builder -> builder.clearClientCapabilities()
                        .addClientCapabilitiesValue(999));
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
        HandshakeAction firstAccepted = sendObservationFrames(replacement.frames());
        assertEquals(1, firstAccepted.outboundFrames().size());
        // Drop the first signed result and retry the exact payload under fresh transfer nonces.
        HandshakeAction retryAccepted = sendObservationFrames(
                client.retryArtifactObservationUpdate(replacement));
        assertTrue(client.receiveArtifactObservationResult(
                retryAccepted.outboundFrames().getFirst(), replacement).accepted());
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
    void bindsSelectedPackIdsToInitialAndDynamicAuthenticatedObservations() throws Exception {
        AtomicReference<AuthenticatedManifest> update = new AtomicReference<>();
        server = new ServerHandshakeCoordinator(
                clock, new SecureRandom(), serverKeys, new RiskEngine(RiskPolicy.defaults()), api,
                Duration.ofSeconds(5), () -> signedPolicy,
                SecurityAuditSink.noop(), ignored -> { }, ignored -> { }, update::set,
                com.ellan.mcace.core.evidence.EvidenceContentStore.discard(),
                com.ellan.mcace.core.evidence.EvidenceAuditSink.noop());
        ClientHandshakeEngine client = client(serverKeys);
        byte[] hello = server.begin(playerId);
        client.prepareServerHello(hello, "test.example:25565",
                new VerifiedPolicyCache(temporaryDirectory.resolve("selected-packs"), clock));
        LoadedModObservation fabric = new LoadedModObservation("fabricloader", "0.19.3",
                LoadedModObservation.OriginKind.BUILTIN_OR_CLASSPATH, "", "");
        List<ClientHandshakeEngine.OutboundFrame> authentication = client.createAuthenticationFrames(
                emptyBundle(), List.of(), List.of("file/xray.zip"), List.of("Complementary"),
                List.of(fabric));
        server.receive(playerId, authentication.get(0).data());
        HandshakeAction authenticated = server.receive(playerId, authentication.get(1).data());
        client.receiveAuthResult(authenticated.outboundFrames().getFirst());

        ClientHandshakeEngine.PreparedArtifactObservationUpdate prepared =
                client.prepareArtifactObservationUpdate(
                        emptyBundle(), List.of(), List.of("file/xray.zip"), List.of("Complementary"),
                        List.of(fabric));
        HandshakeAction accepted = sendObservationFrames(prepared.frames());
        assertTrue(client.receiveArtifactObservationResult(
                accepted.outboundFrames().getFirst(), prepared).accepted());
        client.commitArtifactObservationUpdate(prepared);

        AuthenticatedManifest observed = update.get();
        assertTrue(observed != null);
        assertEquals(List.of("file/xray.zip"), observed.request().getSelectedResourcePacksList());
        assertEquals(List.of("Complementary"), observed.request().getSelectedShaderPacksList());
        assertEquals(1, observed.request().getLoadedModsCount());
        assertEquals("fabricloader", observed.request().getLoadedMods(0).getId());
    }

    @Test
    void invalidUpdateRecoversAndIdempotentAckRequiresExactCanonicalPayload() throws Exception {
        AtomicInteger updates = new AtomicInteger();
        server = new ServerHandshakeCoordinator(
                clock, new SecureRandom(), serverKeys, new RiskEngine(RiskPolicy.defaults()), api,
                Duration.ofSeconds(5), () -> signedPolicy,
                SecurityAuditSink.noop(), ignored -> { }, ignored -> { },
                ignored -> updates.incrementAndGet(),
                com.ellan.mcace.core.evidence.EvidenceContentStore.discard(),
                com.ellan.mcace.core.evidence.EvidenceAuditSink.noop());
        KeyPair clientKeys = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = authenticatedClient(clientKeys, "exact-update");
        ClientHandshakeEngine.PreparedArtifactObservationUpdate prepared =
                client.prepareArtifactObservationUpdate(emptyBundle(), List.of());
        ArtifactObservationUpdate exact = observationUpdate(prepared);

        ArtifactObservationUpdate invalid = exact.toBuilder()
                .addSelectedResourcePacks(" invalid-leading-space")
                .build();
        ArtifactObservationResult invalidResult = verifiedObservationResult(
                sendForgedObservation(invalid, clientKeys));
        assertFalse(invalidResult.getAccepted());
        assertEquals(ArtifactObservationResultReason.ARTIFACT_OBSERVATION_RESULT_INVALID_UPDATE,
                invalidResult.getReason());
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(invalid.toByteArray()),
                invalidResult.getUpdateSha256().toByteArray());
        assertEquals(0, updates.get(), "a semantic rejection cannot advance server state");

        HandshakeAction acceptedButResultDropped = sendObservationFrames(prepared.frames());
        assertTrue(verifiedObservationResult(acceptedButResultDropped).getAccepted());
        assertEquals(1, updates.get());

        ArtifactObservationUpdate sameSequenceRootDifferentPayload = exact.toBuilder()
                .addSelectedResourcePacks("file/changed.zip")
                .build();
        ArtifactObservationResult changed = verifiedObservationResult(
                sendForgedObservation(sameSequenceRootDifferentPayload, clientKeys));
        assertFalse(changed.getAccepted());
        assertEquals(ArtifactObservationResultReason.ARTIFACT_OBSERVATION_RESULT_SEQUENCE_MISMATCH,
                changed.getReason());
        assertEquals(exact.getAggregateRootSha256(), changed.getAggregateRootSha256());
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(
                sameSequenceRootDifferentPayload.toByteArray()), changed.getUpdateSha256().toByteArray());
        assertEquals(1, updates.get(), "same root cannot hide changed loaded/pack semantics");

        HandshakeAction exactRetry = sendObservationFrames(
                client.retryArtifactObservationUpdate(prepared));
        assertTrue(client.receiveArtifactObservationResult(
                exactRetry.outboundFrames().getFirst(), prepared).accepted());
        client.commitArtifactObservationUpdate(prepared);
        assertEquals(1, updates.get(), "exact retry must ACK without duplicate disposition work");
    }

    @Test
    void serverRateLimitsPerSessionAfterAllowingTheFirstImmediateUpdate() throws Exception {
        AtomicInteger updates = new AtomicInteger();
        server = new ServerHandshakeCoordinator(
                clock, new SecureRandom(), serverKeys, new RiskEngine(RiskPolicy.defaults()), api,
                Duration.ofSeconds(5), () -> signedPolicy,
                SecurityAuditSink.noop(), ignored -> { }, ignored -> { },
                ignored -> updates.incrementAndGet(),
                com.ellan.mcace.core.evidence.EvidenceContentStore.discard(),
                com.ellan.mcace.core.evidence.EvidenceAuditSink.noop());
        KeyPair clientKeys = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = authenticatedClient(clientKeys, "rate-limit");
        ClientHandshakeEngine.PreparedArtifactObservationUpdate firstPrepared =
                client.prepareArtifactObservationUpdate(emptyBundle(), List.of());
        ArtifactObservationUpdate first = observationUpdate(firstPrepared);
        HandshakeAction firstAction = sendObservationFrames(firstPrepared.frames());
        assertTrue(client.receiveArtifactObservationResult(
                firstAction.outboundFrames().getFirst(), firstPrepared).accepted());
        client.commitArtifactObservationUpdate(firstPrepared);
        assertEquals(1, updates.get(), "the first changed snapshot is immediate");

        ArtifactObservationUpdate earlySecond = first.toBuilder()
                .setUpdateSequence(2L)
                .setPreviousAggregateRootSha256(first.getAggregateRootSha256())
                .setObservedAtEpochMs(clock.millis())
                .build();
        ArtifactObservationResult limited = verifiedObservationResult(
                sendForgedObservation(earlySecond, clientKeys));
        assertFalse(limited.getAccepted());
        assertEquals(ArtifactObservationResultReason.ARTIFACT_OBSERVATION_RESULT_RATE_LIMITED,
                limited.getReason());
        assertEquals(clock.millis() + ProtocolConstants.ARTIFACT_OBSERVATION_INTERVAL.toMillis(),
                limited.getRetryAfterEpochMs());
        assertEquals(1, updates.get());

        clock.advance(ProtocolConstants.ARTIFACT_OBSERVATION_INTERVAL);
        ArtifactObservationUpdate dueSecond = earlySecond.toBuilder()
                .setObservedAtEpochMs(clock.millis())
                .build();
        ArtifactObservationResult accepted = verifiedObservationResult(
                sendForgedObservation(dueSecond, clientKeys));
        assertTrue(accepted.getAccepted());
        assertEquals(2, updates.get());
    }

    @Test
    void directLoadedModBindingRejectsDowngradeAndDuplicateFilenameButAllowsExplicitUnmatched() throws Exception {
        assertDirectLoadedRequestMutationRejected("matched-false", request -> {
            LoadedModEntry downgraded = request.getLoadedMods(0).toBuilder()
                    .setOriginManifestMatched(false)
                    .setOriginFileSize(0L)
                    .clearOriginSha256()
                    .build();
            return request.toBuilder().setLoadedMods(0, downgraded).build();
        });
        assertDirectLoadedRequestMutationRejected("duplicate-filename", request -> request.toBuilder()
                .addLoadedMods(LoadedModEntry.newBuilder()
                        .setId("second.mod")
                        .setVersion("9")
                        .setOriginKind(LoadedModOriginKind.LOADED_MOD_ORIGIN_MODS_FILE)
                        .setOriginFilename("example.jar"))
                .build());

        resetHandshakeServer();
        KeyPair clientKeys = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = new ClientHandshakeEngine(
                playerId, productVersion(), "1.21.1", "test-build", LoaderType.FABRIC,
                serverKeys.getPublic(), clock, new SecureRandom(), clientKeys);
        client.prepareServerHello(server.begin(playerId), "test.example:25565",
                new VerifiedPolicyCache(temporaryDirectory.resolve("explicit-unmatched"), clock));
        byte[] hash = new byte[32];
        hash[0] = 7;
        ClientIntegrityBundle bundle = bundleWithMod("example.jar", 4L, hash);
        com.ellan.mcace.core.disposition.ArtifactObservation metadata = modMetadata(
                "example.mod", "1.2.3", "example.jar", hash);
        List<ClientHandshakeEngine.OutboundFrame> frames = client.createAuthenticationFrames(
                bundle, List.of(metadata), List.of(), List.of(), List.of(
                        new LoadedModObservation("different.mod", "9",
                                LoadedModObservation.OriginKind.MODS_FILE, "example.jar", ""),
                        new LoadedModObservation("missing.mod", "1",
                                LoadedModObservation.OriginKind.MODS_FILE, "missing.jar", "")));
        AuthRequest request = AuthRequest.parseFrom(
                SignedEnvelope.parseFrom(frames.get(1).data()).getPayload());
        assertTrue(request.getLoadedModsList().stream()
                .noneMatch(LoadedModEntry::getOriginManifestMatched));
        assertFalse(server.receive(playerId, frames.getFirst().data()).protocolViolation());
        HandshakeAction accepted = server.receive(playerId, frames.get(1).data());
        assertFalse(accepted.protocolViolation());
        assertTrue(api.isVerified(playerId));
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
    void defersOneEarlyAuthenticationFrameUntilClientIdentification() throws Exception {
        ClientHandshakeEngine client = client(serverKeys);
        List<byte[]> frames = frames(client, server.begin(playerId));

        HandshakeAction deferred = server.receive(playerId, frames.get(1));
        HandshakeAction completed = server.receive(playerId, frames.get(0));
        AuthResult result = client.receiveAuthResult(completed.outboundFrames().getFirst());

        assertFalse(deferred.protocolViolation());
        assertTrue(deferred.outboundFrames().isEmpty());
        assertTrue(deferred.snapshot().isEmpty());
        assertTrue(result.getAccepted());
        assertEquals(AdmissionStatus.VERIFIED, completed.snapshot().orElseThrow().admissionStatus());
        assertTrue(api.isVerified(playerId));
    }

    @Test
    void rejectsDuplicateAuthenticationFramesBeforeClientIdentification() throws Exception {
        ClientHandshakeEngine client = client(serverKeys);
        List<byte[]> frames = frames(client, server.begin(playerId));

        HandshakeAction deferred = server.receive(playerId, frames.get(1));
        HandshakeAction duplicate = server.receive(playerId, frames.get(1));

        assertFalse(deferred.protocolViolation());
        assertTrue(duplicate.protocolViolation());
        assertEquals(AdmissionStatus.LIMITED, duplicate.snapshot().orElseThrow().admissionStatus());
        assertFalse(api.isVerified(playerId));
    }
    @Test
    void rejectsForgedDeferredAuthenticationAfterClientIdentification() throws Exception {
        ClientHandshakeEngine client = client(serverKeys);
        List<byte[]> frames = frames(client, server.begin(playerId));
        SignedEnvelope original = SignedEnvelope.parseFrom(frames.get(1));
        byte[] signature = original.getSignature().toByteArray();
        signature[0] ^= 0x01;
        byte[] forged = original.toBuilder().setSignature(ByteString.copyFrom(signature)).build().toByteArray();

        HandshakeAction deferred = server.receive(playerId, forged);
        HandshakeAction rejected = server.receive(playerId, frames.get(0));

        assertFalse(deferred.protocolViolation());
        assertTrue(rejected.protocolViolation());
        assertEquals(AdmissionStatus.LIMITED, rejected.snapshot().orElseThrow().admissionStatus());
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
                .setClientVersion(productVersion())
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
                productVersion(),
                "1.21.1",
                "test-build",
                LoaderType.FABRIC,
                pinnedServer.getPublic(),
                clock,
                new SecureRandom());
    }

    private void assertBindingTranscriptRejected(byte[] helloBinding, byte[] requestBinding)
            throws Exception {
        resetHandshakeServer();
        KeyPair clientKeys = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = new ClientHandshakeEngine(
                playerId, productVersion(), "1.21.1", "test-build", LoaderType.FABRIC,
                serverKeys.getPublic(), clock, new SecureRandom(), clientKeys);
        List<byte[]> original = frames(client, server.begin(playerId));
        ClientHello hello = ClientHello.parseFrom(
                SignedEnvelope.parseFrom(original.getFirst()).getPayload()).toBuilder()
                .setFederationSignedAssertionSha256(ByteString.copyFrom(helloBinding))
                .build();
        AuthRequest request = AuthRequest.parseFrom(
                SignedEnvelope.parseFrom(original.get(1)).getPayload()).toBuilder()
                .setFederationSignedAssertionSha256(ByteString.copyFrom(requestBinding))
                .build();
        byte[] helloFrame = resign(original.getFirst(), PacketType.CLIENT_HELLO,
                hello.toByteArray(), clientKeys);
        byte[] requestFrame = resign(original.get(1), PacketType.AUTH_REQUEST,
                request.toByteArray(), clientKeys);

        assertFalse(server.receive(playerId, helloFrame).protocolViolation());
        assertTrue(server.receive(playerId, requestFrame).protocolViolation());
    }

    private void assertHelloBindingRejected(byte[] helloBinding) throws Exception {
        resetHandshakeServer();
        KeyPair clientKeys = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = new ClientHandshakeEngine(
                playerId, productVersion(), "1.21.1", "test-build", LoaderType.FABRIC,
                serverKeys.getPublic(), clock, new SecureRandom(), clientKeys);
        List<byte[]> original = frames(client, server.begin(playerId));
        ClientHello hello = ClientHello.parseFrom(
                SignedEnvelope.parseFrom(original.getFirst()).getPayload()).toBuilder()
                .setFederationSignedAssertionSha256(ByteString.copyFrom(helloBinding))
                .build();
        assertTrue(server.receive(playerId, resign(original.getFirst(), PacketType.CLIENT_HELLO,
                hello.toByteArray(), clientKeys)).protocolViolation());
    }

    private byte[] resign(byte[] originalFrame, PacketType type, byte[] payload, KeyPair clientKeys)
            throws Exception {
        String sessionId = SignedEnvelope.parseFrom(originalFrame).getHeader().getSessionId();
        return new EnvelopeCodec(clock, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES,
                ProtocolConstants.DEFAULT_CLOCK_SKEW)
                .sign(type, sessionId, payload, clientKeys.getPrivate()).toByteArray();
    }

    private void resetHandshakeServer() throws EnvelopeException {
        api = new InMemoryMCAceApi();
        server = new ServerHandshakeCoordinator(
                clock, new SecureRandom(), serverKeys, new RiskEngine(RiskPolicy.defaults()), api,
                Duration.ofSeconds(5), () -> signedPolicy);
        playerId = UUID.randomUUID();
    }

    private List<byte[]> frames(ClientHandshakeEngine client, byte[] hello) throws Exception {
        client.prepareServerHello(hello, "test.example:25565",
                new VerifiedPolicyCache(temporaryDirectory.resolve(UUID.randomUUID().toString()), clock));
        return client.createAuthentication(emptyBundle());
    }

    private HandshakeAction sendObservationFrames(
            List<ClientHandshakeEngine.OutboundFrame> frames) {
        HandshakeAction action = HandshakeAction.none();
        for (ClientHandshakeEngine.OutboundFrame frame : frames) {
            action = server.receive(playerId, frame.data());
        }
        return action;
    }

    private ClientHandshakeEngine authenticatedClient(KeyPair clientKeys, String cacheSuffix)
            throws Exception {
        ClientHandshakeEngine client = new ClientHandshakeEngine(
                playerId, productVersion(), "1.21.1", "test-build", LoaderType.FABRIC,
                serverKeys.getPublic(), clock, new SecureRandom(), clientKeys);
        client.prepareServerHello(server.begin(playerId), "test.example:25565",
                new VerifiedPolicyCache(temporaryDirectory.resolve(cacheSuffix), clock));
        List<byte[]> authentication = client.createAuthentication(emptyBundle());
        assertFalse(server.receive(playerId, authentication.getFirst()).protocolViolation());
        HandshakeAction accepted = server.receive(playerId, authentication.get(1));
        assertTrue(client.receiveAuthResult(accepted.outboundFrames().getFirst()).getAccepted());
        return client;
    }

    private ArtifactObservationUpdate observationUpdate(
            ClientHandshakeEngine.PreparedArtifactObservationUpdate prepared) throws Exception {
        BoundedPayloadTransferReceiver receiver = new BoundedPayloadTransferReceiver(
                server.currentAuthenticatedSessionId(playerId).orElseThrow(), clock,
                ProtocolConstants.DEFAULT_BOUNDED_PAYLOAD_TTL);
        java.util.Optional<BoundedPayloadTransferReceiver.CompletedPayload> completed =
                java.util.Optional.empty();
        for (ClientHandshakeEngine.OutboundFrame frame : prepared.frames()) {
            completed = receiver.acceptVerified(SignedEnvelope.parseFrom(frame.data()));
        }
        return ArtifactObservationUpdate.parseFrom(completed.orElseThrow().content());
    }

    private HandshakeAction sendForgedObservation(
            ArtifactObservationUpdate update, KeyPair clientKeys) throws Exception {
        String sessionId = server.currentAuthenticatedSessionId(playerId).orElseThrow();
        List<byte[]> frames = new BoundedPayloadTransferSender().send(
                BoundedPayloadKind.BOUNDED_PAYLOAD_ARTIFACT_OBSERVATION,
                sessionId, update.toByteArray(), update.getAggregateRootSha256().toByteArray(), 1L,
                new EnvelopeCodec(clock, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES,
                        ProtocolConstants.DEFAULT_CLOCK_SKEW),
                clientKeys.getPrivate());
        HandshakeAction action = HandshakeAction.none();
        for (byte[] frame : frames) action = server.receive(playerId, frame);
        return action;
    }

    private ArtifactObservationResult verifiedObservationResult(HandshakeAction action)
            throws Exception {
        assertEquals(1, action.outboundFrames().size());
        SignedEnvelope envelope = SignedEnvelope.parseFrom(action.outboundFrames().getFirst());
        new EnvelopeCodec(clock, new SecureRandom(), ProtocolConstants.MAX_PAYLOAD_BYTES,
                ProtocolConstants.DEFAULT_CLOCK_SKEW).verify(
                        envelope, serverKeys.getPublic(),
                        new NonceReplayGuard(clock, ProtocolConstants.DEFAULT_REPLAY_WINDOW));
        assertEquals(PacketType.ARTIFACT_OBSERVATION_RESULT,
                envelope.getHeader().getPacketType());
        return ArtifactObservationResult.parseFrom(envelope.getPayload());
    }

    private void assertDirectLoadedRequestMutationRejected(
            String cacheSuffix,
            java.util.function.UnaryOperator<AuthRequest> mutation) throws Exception {
        resetHandshakeServer();
        KeyPair clientKeys = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = new ClientHandshakeEngine(
                playerId, productVersion(), "1.21.1", "test-build", LoaderType.FABRIC,
                serverKeys.getPublic(), clock, new SecureRandom(), clientKeys);
        client.prepareServerHello(server.begin(playerId), "test.example:25565",
                new VerifiedPolicyCache(temporaryDirectory.resolve("direct-" + cacheSuffix), clock));
        byte[] hash = new byte[32];
        hash[0] = 11;
        ClientIntegrityBundle bundle = bundleWithMod("example.jar", 4L, hash);
        com.ellan.mcace.core.disposition.ArtifactObservation metadata = modMetadata(
                "example.mod", "1.2.3", "example.jar", hash);
        LoadedModObservation loaded = new LoadedModObservation(
                "example.mod", "1.2.3", LoadedModObservation.OriginKind.MODS_FILE,
                "example.jar", "");
        List<ClientHandshakeEngine.OutboundFrame> frames = client.createAuthenticationFrames(
                bundle, List.of(metadata), List.of(), List.of(), List.of(loaded));
        AuthRequest original = AuthRequest.parseFrom(
                SignedEnvelope.parseFrom(frames.get(1).data()).getPayload());
        assertTrue(original.getLoadedMods(0).getOriginManifestMatched());

        assertFalse(server.receive(playerId, frames.getFirst().data()).protocolViolation());
        HandshakeAction rejected = server.receive(playerId, resign(
                frames.get(1).data(), PacketType.AUTH_REQUEST,
                mutation.apply(original).toByteArray(), clientKeys));
        assertTrue(rejected.protocolViolation());
        assertFalse(api.isVerified(playerId));
    }

    private static com.ellan.mcace.core.disposition.ArtifactObservation modMetadata(
            String id, String version, String filename, byte[] sha256) {
        return new com.ellan.mcace.core.disposition.ArtifactObservation(
                com.ellan.mcace.core.disposition.ArtifactType.MOD,
                id, version, java.util.HexFormat.of().formatHex(sha256),
                java.util.Map.of("scope", "mods", "artifact_path", filename),
                com.ellan.mcace.core.disposition.ObservationOrigin.CLIENT_REPORTED,
                com.ellan.mcace.core.disposition.Confidence.LOW,
                false);
    }

    private ClientIntegrityBundle emptyBundle() throws Exception {
        return ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, clock.instant(), List.of(), IntegrityDigests.scopeRoot(List.of()))));
    }

    private ClientIntegrityBundle bundleWithMod(String filename, long size, byte[] sha256) throws Exception {
        IntegrityEntry entry = new IntegrityEntry(filename, size, sha256);
        com.ellan.mcace.protocol.generated.FileEntry wire =
                com.ellan.mcace.protocol.generated.FileEntry.newBuilder()
                        .setRelativePath(filename).setFileSize(size)
                        .setSha256(ByteString.copyFrom(sha256)).build();
        return ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, clock.instant(), List.of(entry),
                IntegrityDigests.scopeRoot(List.of(wire)))));
    }

    private void assertLoadedGraphRequestMutationRejected(
            String cacheSuffix,
            java.util.function.UnaryOperator<AuthRequest.Builder> mutation) throws Exception {
        resetHandshakeServer();
        KeyPair clientKeys = Ed25519Keys.generate(new SecureRandom());
        ClientHandshakeEngine client = new ClientHandshakeEngine(
                playerId, productVersion(), "1.21.1", "test-build", LoaderType.FABRIC,
                serverKeys.getPublic(), clock, new SecureRandom(), clientKeys);
        byte[] hello = server.begin(playerId);
        client.prepareServerHello(hello, "test.example:25565",
                new VerifiedPolicyCache(temporaryDirectory.resolve("loaded-capability-" + cacheSuffix), clock));
        LoadedModObservation fabric = new LoadedModObservation(
                "fabricloader", "0.19.3", LoadedModObservation.OriginKind.BUILTIN_OR_CLASSPATH, "", "");
        List<ClientHandshakeEngine.OutboundFrame> frames = client.createAuthenticationFrames(
                emptyBundle(), List.of(), List.of(), List.of(), List.of(fabric));
        AuthRequest original = AuthRequest.parseFrom(
                SignedEnvelope.parseFrom(frames.get(1).data()).getPayload());
        AuthRequest forged = mutation.apply(original.toBuilder()).build();

        assertFalse(server.receive(playerId, frames.getFirst().data()).protocolViolation());
        assertTrue(server.receive(playerId, resign(
                frames.get(1).data(), PacketType.AUTH_REQUEST, forged.toByteArray(), clientKeys)).protocolViolation());
        assertFalse(api.isVerified(playerId));
    }

    private SignedPolicyDocument signedPolicyRequiringLoadedGraph() throws Exception {
        KeyPair delegate = Ed25519Keys.generate(new SecureRandom());
        SecurityPolicy base = SecurityPolicy.parseFrom(signedPolicy.getPolicy());
        SecurityPolicy policy = base.toBuilder()
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(delegate.getPublic())))
                .addRequiredClientCapabilities(ClientCapability.CLIENT_CAPABILITY_LOADED_MOD_GRAPH_V1)
                .build();
        var trust = PolicyDocuments.signTrustStatement(PolicyTrustStatement.newBuilder()
                .setSequence(1).setServerId(policy.getServerId())
                .setIssuedAtEpochMs(clock.millis())
                .setExpiresAtEpochMs(clock.millis() + Duration.ofDays(30).toMillis())
                .setRootKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(serverKeys.getPublic())))
                .addDelegatedSigningKeys(DelegatedSigningKey.newBuilder()
                        .setKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(delegate.getPublic())))
                        .setPublicKeyX509(ByteString.copyFrom(delegate.getPublic().getEncoded()))
                        .setNotBeforeEpochMs(clock.millis())
                        .setNotAfterEpochMs(clock.millis() + Duration.ofDays(14).toMillis()))
                .build(), serverKeys.getPrivate(), serverKeys.getPublic());
        return PolicyDocuments.signDelegated(policy, delegate.getPrivate(), delegate.getPublic(), trust);
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
