package com.ellan.mcace.client.session;

import com.ellan.mcace.client.integrity.IntegrityEntry;
import com.ellan.mcace.client.integrity.ClientIntegrityBundle;
import com.ellan.mcace.client.integrity.IntegrityScanCancellation;
import com.ellan.mcace.client.integrity.IntegrityScanException;
import com.ellan.mcace.client.integrity.PolicyDrivenIntegrityCollector;
import com.ellan.mcace.client.observation.ArtifactObservationCollector;
import com.ellan.mcace.client.integrity.ScopeIntegrityManifest;
import com.ellan.mcace.client.policy.VerifiedPolicy;
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
import com.ellan.mcace.protocol.generated.AuthRequest;
import com.ellan.mcace.protocol.generated.AuthResult;
import com.ellan.mcace.protocol.generated.ArtifactObservationUpdate;
import com.ellan.mcace.protocol.generated.ClientHello;
import com.ellan.mcace.protocol.generated.EvidenceBegin;
import com.ellan.mcace.protocol.generated.EvidenceAck;
import com.ellan.mcace.protocol.generated.EvidenceAckStatus;
import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceChunk;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import com.ellan.mcace.protocol.generated.EvidenceCommit;
import com.ellan.mcace.protocol.generated.EvidenceError;
import com.ellan.mcace.protocol.generated.EvidenceErrorCode;
import com.ellan.mcace.protocol.generated.EvidenceRequest;
import com.ellan.mcace.protocol.generated.EvidenceResponse;
import com.ellan.mcace.protocol.generated.EvidenceType;
import com.ellan.mcace.protocol.generated.FileEntry;
import com.ellan.mcace.protocol.generated.Heartbeat;
import com.ellan.mcace.protocol.generated.IntegrityScopeManifest;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.ModEntry;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.ServerHello;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.protocol.policy.PolicyException;
import com.ellan.mcace.protocol.transport.BoundedPayloadException;
import com.ellan.mcace.protocol.transport.BoundedPayloadTransferLimits;
import com.ellan.mcace.protocol.transport.BoundedPayloadTransferSender;
import com.ellan.mcace.protocol.evidence.EvidenceTransferLimits;
import com.ellan.mcace.protocol.evidence.EvidenceRequestVerifier;
import com.ellan.mcace.client.evidence.ChunkedEvidencePayload;
import com.ellan.mcace.client.evidence.EvidencePayloadChunk;
import com.ellan.mcace.client.evidence.EvidencePayloadChunker;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public final class ClientHandshakeEngine {
    private static final int MAX_PENDING_EVIDENCE_REQUESTS = 8;
    private final UUID playerId;
    private final String clientVersion;
    private final String minecraftVersion;
    private final String buildId;
    private final LoaderType loader;
    private final PublicKey serverPublicKey;
    private final KeyPair sessionKeyPair;
    private final Clock clock;
    private final EnvelopeCodec envelopeCodec;
    private final NonceReplayGuard replayGuard;
    private String sessionId;
    private ServerHello acceptedHello;
    private VerifiedPolicy verifiedPolicy;
    /** Frozen only after a complete local AuthRequest has been prepared for this session. */
    private HeartbeatBinding pendingHeartbeatBinding;
    /** Present only once the server has signed an accepted AuthResult for that request. */
    private HeartbeatBinding acceptedHeartbeatBinding;
    private boolean authenticationResultReceived;
    private long nextHeartbeatSequence;
    /** Client-local, signed complete-snapshot sequence.  This is independent of heartbeat wires. */
    private long nextArtifactObservationSequence;
    private long lastArtifactObservationAtEpochMs;
    private byte[] lastArtifactObservationAggregateRoot;
    /** Verified, one-shot evidence requests for this authenticated session. */
    private final Map<String, VerifiedEvidenceRequest> pendingEvidenceRequests = new HashMap<>();
    /** Request IDs for which the visible UI has already produced its sole in-memory grant. */
    private final Set<String> issuedEvidenceConsents = new HashSet<>();
    /** Last wire sequence that must be observed before a signed COMPLETE can finish a request. */
    private final Map<String, Long> pendingEvidenceFinalSequences = new HashMap<>();
    /** Last strictly increasing server acknowledgement/error sequence per request. */
    private final Map<String, Long> pendingEvidenceServerSequences = new HashMap<>();
    /** Consent requests awaiting exactly one source-server-signed grant; never persisted. */
    private final Map<String, com.ellan.mcace.protocol.generated.FederationConsentRequest>
            pendingFederationConsentRequests = new HashMap<>();
    private EvidenceRequestVerifier evidenceRequestVerifier;

    public ClientHandshakeEngine(
            UUID playerId,
            String clientVersion,
            String minecraftVersion,
            String buildId,
            LoaderType loader,
            PublicKey serverPublicKey,
            Clock clock,
            SecureRandom secureRandom) throws EnvelopeException {
        this(playerId, clientVersion, minecraftVersion, buildId, loader, serverPublicKey, clock,
                secureRandom, Ed25519Keys.generate(secureRandom));
    }

    /**
     * Uses a still-live in-memory Ed25519 key only for a federation target handshake. The
     * bounded transfer vault owns the key and never serializes or exposes it to a caller.
     */
    public ClientHandshakeEngine(
            UUID playerId,
            String clientVersion,
            String minecraftVersion,
            String buildId,
            LoaderType loader,
            PublicKey serverPublicKey,
            Clock clock,
            SecureRandom secureRandom,
            KeyPair sessionKeyPair) throws EnvelopeException {
        this.playerId = Objects.requireNonNull(playerId, "playerId");
        this.clientVersion = requireText(clientVersion, "clientVersion");
        this.minecraftVersion = requireText(minecraftVersion, "minecraftVersion");
        this.buildId = requireText(buildId, "buildId");
        this.loader = Objects.requireNonNull(loader, "loader");
        if (loader == LoaderType.LOADER_UNSPECIFIED || loader == LoaderType.UNRECOGNIZED) {
            throw new IllegalArgumentException("loader must be specified");
        }
        this.serverPublicKey = Objects.requireNonNull(serverPublicKey, "serverPublicKey");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.sessionKeyPair = Objects.requireNonNull(sessionKeyPair, "sessionKeyPair");
        if (sessionKeyPair.getPrivate() == null || sessionKeyPair.getPublic() == null) {
            throw new EnvelopeException("federation session key pair is incomplete");
        }
        this.envelopeCodec = new EnvelopeCodec(
                this.clock,
                secureRandom,
                ProtocolConstants.MAX_PAYLOAD_BYTES,
                ProtocolConstants.DEFAULT_CLOCK_SKEW);
        this.replayGuard = new NonceReplayGuard(this.clock, ProtocolConstants.DEFAULT_REPLAY_WINDOW);
    }

    public synchronized VerifiedPolicy prepareServerHello(
            byte[] encodedFrame,
            String serverAddress,
            VerifiedPolicyCache policyCache)
            throws EnvelopeException {
        Objects.requireNonNull(policyCache, "policyCache");
        SignedEnvelope envelope = envelopeCodec.parse(encodedFrame);
        envelopeCodec.verify(envelope, serverPublicKey, replayGuard);
        if (envelope.getHeader().getPacketType() != PacketType.SERVER_HELLO || sessionId != null) {
            throw new EnvelopeException("unexpected server handshake packet");
        }
        try {
            ServerHello hello = ServerHello.parseFrom(envelope.getPayload());
            if (hello.getChallengeNonce().size() != ProtocolConstants.NONCE_BYTES
                    || hello.getRequiredLevel().getNumber() > TrustLevel.VERIFIED.getNumber()
                    || !hello.hasSignedPolicy()) {
                throw new EnvelopeException("unsupported or malformed server challenge");
            }
            VerifiedPolicy accepted = policyCache.accept(serverAddress, hello.getSignedPolicy(), serverPublicKey);
            if (!hello.getServerId().equals(accepted.policy().getServerId())
                    || !hello.getPolicyVersion().equals(accepted.policy().getPolicyVersion())
                    || hello.getRequiredLevel() != accepted.policy().getRequiredLevel()
                    || !accepted.policy().getAllowedMinecraftVersionsList().contains(minecraftVersion)
                    || !accepted.policy().getAllowedLoadersList().contains(loader)
                    || (accepted.policy().getAllowedBuildIdsCount() > 0
                        && !accepted.policy().getAllowedBuildIdsList().contains(buildId))) {
                throw new EnvelopeException("server policy is incompatible with this client");
            }
            sessionId = envelope.getHeader().getSessionId();
            acceptedHello = hello;
            verifiedPolicy = accepted;
            pendingHeartbeatBinding = null;
            acceptedHeartbeatBinding = null;
            authenticationResultReceived = false;
            nextHeartbeatSequence = 0;
            nextArtifactObservationSequence = 0;
            lastArtifactObservationAtEpochMs = 0;
            lastArtifactObservationAggregateRoot = null;
            pendingEvidenceRequests.clear();
            issuedEvidenceConsents.clear();
            pendingEvidenceFinalSequences.clear();
            pendingEvidenceServerSequences.clear();
            pendingFederationConsentRequests.clear();
            evidenceRequestVerifier = new EvidenceRequestVerifier(clock);
            return accepted;
        } catch (InvalidProtocolBufferException exception) {
            throw new EnvelopeException("malformed server hello", exception);
        } catch (IOException | PolicyException exception) {
            throw new EnvelopeException("server policy verification failed", exception);
        }
    }

    public synchronized List<byte[]> createAuthentication(ClientIntegrityBundle bundle) throws EnvelopeException {
        return createAuthentication(bundle, List.of());
    }

    /**
     * Creates the signed authentication frames with optional, locally derived Fabric mod metadata.
     *
     * <p>Every supplied observation is treated as untrusted self-reporting and must map exactly to
     * one entry in the already policy-authorized integrity bundle.  Only the matching MOD
     * observation can enrich the corresponding {@link ModEntry}; resource-pack and shader
     * observations are validated for scope integrity but never turn into a finding here.
     */
    public synchronized List<byte[]> createAuthentication(
            ClientIntegrityBundle bundle, List<ArtifactObservation> observations) throws EnvelopeException {
        List<OutboundFrame> frames = createAuthenticationFrames(bundle, observations);
        if (frames.stream().anyMatch(frame -> frame.channel() != OutboundChannel.HANDSHAKE)) {
            throw new EnvelopeException("authentication requires bounded payload transport; use createAuthenticationFrames");
        }
        return frames.stream().map(OutboundFrame::data).toList();
    }

    /**
     * Creates ordered frames for the two fixed client channels.  The client hello is always first
     * on {@link OutboundChannel#HANDSHAKE}; a small authentication request remains the legacy
     * AUTH_REQUEST frame, while a larger valid request is atomically represented as a complete
     * payload-channel BEGIN/CHUNK/COMMIT sequence.
     */
    public synchronized List<OutboundFrame> createAuthenticationFrames(ClientIntegrityBundle bundle)
            throws EnvelopeException {
        return createAuthenticationFrames(bundle, List.of());
    }

    public synchronized List<OutboundFrame> createAuthenticationFrames(
            ClientIntegrityBundle bundle, List<ArtifactObservation> observations) throws EnvelopeException {
        Objects.requireNonNull(bundle, "bundle");
        Objects.requireNonNull(observations, "observations");
        if (sessionId == null || acceptedHello == null || verifiedPolicy == null) {
            throw new EnvelopeException("server hello has not been accepted");
        }
        if (authenticationResultReceived) {
            throw new EnvelopeException("authentication was already completed for this session");
        }
        ClientHello clientHello = ClientHello.newBuilder()
                .setClientVersion(clientVersion)
                .setLoader(loader)
                .setMinecraftVersion(minecraftVersion)
                .setPublicKeyX509(ByteString.copyFrom(sessionKeyPair.getPublic().getEncoded()))
                .setBuildId(buildId)
                .setChallengeNonce(acceptedHello.getChallengeNonce())
                .build();
        AuthRequest authentication = buildAuthentication(bundle, verifiedPolicy, observations);
        byte[] helloFrame = signedFrame(PacketType.CLIENT_HELLO, clientHello.toByteArray());
        byte[] authenticationPayload = authentication.toByteArray();
        byte[] legacyAuthenticationFrame = signedFrame(PacketType.AUTH_REQUEST, authenticationPayload);
        List<OutboundFrame> frames = new ArrayList<>();
        frames.add(new OutboundFrame(OutboundChannel.HANDSHAKE, helloFrame));
        List<OutboundFrame> result;
        if (legacyAuthenticationFrame.length <= ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES) {
            frames.add(new OutboundFrame(OutboundChannel.HANDSHAKE, legacyAuthenticationFrame));
            result = List.copyOf(frames);
        } else {
            try {
                List<byte[]> fragments = new BoundedPayloadTransferSender().send(
                        com.ellan.mcace.protocol.generated.BoundedPayloadKind.BOUNDED_PAYLOAD_AUTH_REQUEST,
                        sessionId,
                        authenticationPayload,
                        authentication.getManifestRootSha256().toByteArray(),
                        1,
                        envelopeCodec,
                        sessionKeyPair.getPrivate());
                for (byte[] fragment : fragments) {
                    frames.add(new OutboundFrame(OutboundChannel.PAYLOAD, fragment));
                }
                result = List.copyOf(frames);
            } catch (BoundedPayloadException exception) {
                throw new EnvelopeException("authentication payload cannot be transferred within protocol limits", exception);
            }
        }
        pendingHeartbeatBinding = new HeartbeatBinding(
                authentication.getManifestRootSha256().toByteArray(),
                authentication.getPolicySequence(),
                authentication.getPolicySha256().toByteArray(),
                bundle.aggregateRootSha256(),
                acceptedHello.getServerId());
        return result;
    }

    public synchronized AuthResult receiveAuthResult(byte[] encodedFrame) throws EnvelopeException {
        if (sessionId == null) {
            throw new EnvelopeException("handshake has not started");
        }
        SignedEnvelope envelope = envelopeCodec.parse(encodedFrame);
        envelopeCodec.verify(envelope, serverPublicKey, replayGuard);
        if (envelope.getHeader().getPacketType() != PacketType.AUTH_RESULT
                || !sessionId.equals(envelope.getHeader().getSessionId())) {
            throw new EnvelopeException("unexpected authentication result");
        }
        try {
            if (authenticationResultReceived) {
                throw new EnvelopeException("authentication result was already received for this session");
            }
            AuthResult result = AuthResult.parseFrom(envelope.getPayload());
            if (result.getAccepted()) {
                if (pendingHeartbeatBinding == null) {
                    throw new EnvelopeException("accepted authentication result has no locally prepared binding");
                }
                if (result.getTrustLevel() != TrustLevel.VERIFIED
                        || result.getExpiresAtEpochMs() <= clock.millis()) {
                    throw new EnvelopeException("accepted authentication result is not a current verified session");
                }
                acceptedHeartbeatBinding = pendingHeartbeatBinding;
                nextHeartbeatSequence = 0;
                nextArtifactObservationSequence = 0;
                lastArtifactObservationAtEpochMs = 0;
                lastArtifactObservationAggregateRoot = null;
            } else {
                pendingHeartbeatBinding = null;
                acceptedHeartbeatBinding = null;
                nextHeartbeatSequence = 0;
                pendingEvidenceRequests.clear();
                pendingEvidenceFinalSequences.clear();
                pendingEvidenceServerSequences.clear();
                pendingFederationConsentRequests.clear();
            }
            authenticationResultReceived = true;
            return result;
        } catch (InvalidProtocolBufferException exception) {
            throw new EnvelopeException("malformed authentication result", exception);
        }
    }

    /**
     * Builds one bounded, signed heartbeat from the exact manifests and policy already accepted
     * during authentication. This method performs no filesystem work and never exposes the
     * session private key.
     */
    public synchronized byte[] createHeartbeat() throws EnvelopeException {
        if (sessionId == null || acceptedHeartbeatBinding == null) {
            throw new EnvelopeException("heartbeat is unavailable before accepted authentication");
        }
        // AuthResult.expires_at is admission-result freshness, not the heartbeat
        // lease. The signed result is still required to be current when received;
        // this session can then continue until its transport/session is removed.
        if (nextHeartbeatSequence == Long.MAX_VALUE) {
            throw new EnvelopeException("heartbeat sequence is exhausted");
        }
        long sequence = nextHeartbeatSequence + 1L;
        if (sequence <= 0L) {
            throw new EnvelopeException("heartbeat sequence overflowed");
        }
        HeartbeatBinding binding = acceptedHeartbeatBinding;
        Heartbeat heartbeat = Heartbeat.newBuilder()
                .setSequence(sequence)
                .setCurrentServer(binding.currentServer())
                .setClientStatus(TrustLevel.VERIFIED)
                .setManifestRootSha256(ByteString.copyFrom(binding.manifestRoot()))
                .setPolicySequence(binding.policySequence())
                .setPolicySha256(ByteString.copyFrom(binding.policyHash()))
                .setAggregateRootSha256(ByteString.copyFrom(binding.aggregateRoot()))
                .build();
        byte[] frame = signedFrame(PacketType.HEARTBEAT, heartbeat.toByteArray());
        nextHeartbeatSequence = sequence;
        return frame;
    }

    public synchronized boolean heartbeatReady() {
        return acceptedHeartbeatBinding != null;
    }

    /**
     * Returns the server ID only after the signed {@code SERVER_HELLO} and its policy have been
     * fully verified. This is deliberately separate from the federation-authenticated accessors:
     * callers may use it to select a target-bound session key before they construct the
     * authentication request, but must never make that choice from an unverified envelope.
     */
    public synchronized String verifiedServerId() throws EnvelopeException {
        if (sessionId == null || acceptedHello == null || verifiedPolicy == null) {
            throw new EnvelopeException("federation server identity requires a verified server hello");
        }
        return acceptedHello.getServerId();
    }

    /** Federation-only bindings from the verified target hello; returned defensively. */
    public synchronized String authenticatedSessionId() throws EnvelopeException {
        requireFederationAuthenticated();
        return sessionId;
    }

    public synchronized String authenticatedServerId() throws EnvelopeException {
        requireFederationAuthenticated();
        return acceptedHello.getServerId();
    }

    public synchronized byte[] federationChallengeNonce() throws EnvelopeException {
        requireFederationAuthenticated();
        return acceptedHello.getChallengeNonce().toByteArray();
    }

    /**
     * Verifies a source-server-signed consent request. This does not imply consent: only the
     * caller's subsequent, visible Allow once action may call {@link #createFederationConsentFrame}.
     */
    public synchronized VerifiedFederationConsentRequest receiveFederationConsentRequest(byte[] encodedFrame)
            throws EnvelopeException {
        requireFederationAuthenticated();
        SignedEnvelope envelope = envelopeCodec.parse(encodedFrame);
        envelopeCodec.verify(envelope, serverPublicKey, replayGuard);
        if (envelope.getHeader().getPacketType()
                        != com.ellan.mcace.protocol.generated.PacketType.FEDERATION_CONSENT_REQUEST
                || !sessionId.equals(envelope.getHeader().getSessionId())) {
            throw new EnvelopeException("unexpected federation consent request");
        }
        try {
            com.ellan.mcace.protocol.generated.FederationConsentRequest request =
                    com.ellan.mcace.protocol.federation.FederationDocuments.parseConsentRequest(
                            envelope.getPayload().toByteArray(), clock, ProtocolConstants.DEFAULT_CLOCK_SKEW);
            validateFederationRequestBinding(request);
            return new VerifiedFederationConsentRequest(request);
        } catch (com.ellan.mcace.protocol.federation.FederationException exception) {
            throw new EnvelopeException("malformed federation consent request", exception);
        }
    }

    /** Creates a request-bound consent frame only after the Fabric UI explicitly allowed it. */
    public synchronized byte[] createFederationConsentFrame(VerifiedFederationConsentRequest request)
            throws EnvelopeException {
        requireFederationAuthenticated();
        Objects.requireNonNull(request, "request");
        validateFederationRequestBinding(request.request());
        try {
            com.ellan.mcace.protocol.generated.ClientFederationConsent consent =
                    com.ellan.mcace.protocol.federation.FederationDocuments.signClientConsent(
                            request.request(), sessionKeyPair.getPrivate(), sessionKeyPair.getPublic(), clock,
                            ProtocolConstants.DEFAULT_CLOCK_SKEW);
            byte[] frame = signedFrame(com.ellan.mcace.protocol.generated.PacketType.FEDERATION_CONSENT_RESPONSE,
                    com.ellan.mcace.protocol.federation.FederationDocuments.encodeConsentResponse(consent));
            if (pendingFederationConsentRequests.putIfAbsent(request.request().getAssertionId(), request.request())
                    != null) {
                throw new EnvelopeException("federation consent was already sent for this request");
            }
            return frame;
        } catch (com.ellan.mcace.protocol.federation.FederationException exception) {
            throw new EnvelopeException("could not sign federation consent", exception);
        }
    }

    /** Transfers a source-server-signed grant directly into the volatile federation vault. */
    public synchronized void receiveFederationGrant(
            byte[] encodedFrame, com.ellan.mcace.client.federation.FederationTokenVault vault)
            throws EnvelopeException {
        requireFederationAuthenticated();
        Objects.requireNonNull(vault, "vault");
        SignedEnvelope envelope = envelopeCodec.parse(encodedFrame);
        envelopeCodec.verify(envelope, serverPublicKey, replayGuard);
        if (envelope.getHeader().getPacketType()
                        != com.ellan.mcace.protocol.generated.PacketType.FEDERATION_GRANT
                || !sessionId.equals(envelope.getHeader().getSessionId())) {
            throw new EnvelopeException("unexpected federation grant");
        }
        try {
            com.ellan.mcace.protocol.generated.FederationGrant parsed =
                    com.ellan.mcace.protocol.generated.FederationGrant.parseFrom(envelope.getPayload());
            com.ellan.mcace.protocol.generated.FederationConsentRequest pending =
                    pendingFederationConsentRequests.remove(parsed.getClientConsent().getAssertionId());
            if (pending == null) {
                throw new EnvelopeException("federation grant has no current consent request");
            }
            com.ellan.mcace.protocol.generated.FederationGrant grant =
                    com.ellan.mcace.protocol.federation.FederationDocuments.verifyGrant(
                            envelope.getPayload().toByteArray(), pending, sessionKeyPair.getPublic(), serverPublicKey,
                            clock, ProtocolConstants.DEFAULT_CLOCK_SKEW);
            vault.store(grant, sessionKeyPair, playerId, sessionId, clock);
        } catch (InvalidProtocolBufferException exception) {
            throw new EnvelopeException("malformed federation grant", exception);
        } catch (com.ellan.mcace.protocol.federation.FederationException exception) {
            throw new EnvelopeException("rejected federation grant", exception);
        }
    }

    /** Cancels an unsent consent response; a later grant for it will fail closed. */
    public synchronized void cancelFederationConsent(VerifiedFederationConsentRequest request) {
        if (request != null) {
            pendingFederationConsentRequests.remove(request.request().getAssertionId());
        }
    }

    /** Signs a bounded federation presentation after this target's local authentication succeeds. */
    public synchronized byte[] createFederationPresentationFrame(byte[] encodedPresentation)
            throws EnvelopeException {
        requireFederationAuthenticated();
        if (encodedPresentation == null || encodedPresentation.length == 0
                || encodedPresentation.length > ProtocolConstants.MAX_FEDERATION_PRESENTATION_BYTES) {
            throw new EnvelopeException("invalid federation presentation payload");
        }
        return signedFrame(com.ellan.mcace.protocol.generated.PacketType.FEDERATION_PRESENTATION,
                encodedPresentation);
    }

    /**
     * Creates a complete, low-frequency post-authentication observation snapshot.
     *
     * <p>The caller supplies a fresh {@link ClientIntegrityBundle} produced only by the already
     * signed policy's scopes. This method does not accept paths, arbitrary observations, or an
     * alternate policy. It is optional telemetry: a client which never calls it remains verified.
     */
    public synchronized PreparedArtifactObservationUpdate prepareArtifactObservationUpdate(
            ClientIntegrityBundle bundle, List<ArtifactObservation> observations) throws EnvelopeException {
        Objects.requireNonNull(bundle, "bundle");
        Objects.requireNonNull(observations, "observations");
        if (sessionId == null || acceptedHeartbeatBinding == null || verifiedPolicy == null
                || !authenticationResultReceived) {
            throw new EnvelopeException("artifact observations require accepted authentication");
        }
        long now = clock.millis();
        if (lastArtifactObservationAtEpochMs != 0L
                && now - lastArtifactObservationAtEpochMs < ProtocolConstants.ARTIFACT_OBSERVATION_INTERVAL.toMillis()) {
            throw new EnvelopeException("artifact observation interval has not elapsed");
        }
        if (nextArtifactObservationSequence == Long.MAX_VALUE) {
            throw new EnvelopeException("artifact observation sequence is exhausted");
        }
        AuthRequest snapshot = buildAuthentication(bundle, verifiedPolicy, observations);
        if (snapshot.getModsCount() > ProtocolConstants.MAX_ARTIFACT_OBSERVATION_COUNT
                || snapshot.getScopeManifestsList().stream().mapToInt(IntegrityScopeManifest::getEntriesCount).sum()
                > ProtocolConstants.MAX_ARTIFACT_OBSERVATION_COUNT) {
            throw new EnvelopeException("artifact observation exceeds entry budget");
        }
        HeartbeatBinding binding = acceptedHeartbeatBinding;
        ArtifactObservationUpdate update = ArtifactObservationUpdate.newBuilder()
                .setUpdateSequence(nextArtifactObservationSequence + 1L)
                .setBaseManifestRootSha256(ByteString.copyFrom(binding.manifestRoot()))
                .setPreviousAggregateRootSha256(ByteString.copyFrom(lastArtifactObservationAggregateRoot == null
                        ? binding.aggregateRoot() : lastArtifactObservationAggregateRoot))
                .setAggregateRootSha256(ByteString.copyFrom(bundle.aggregateRootSha256()))
                .setObservedAtEpochMs(now)
                .addAllMods(snapshot.getModsList())
                .addAllScopeManifests(snapshot.getScopeManifestsList())
                .setPolicySha256(ByteString.copyFrom(binding.policyHash()))
                .setPolicySequence(binding.policySequence())
                .build();
        byte[] payload = update.toByteArray();
        try {
            List<byte[]> fragments = new BoundedPayloadTransferSender().send(
                    com.ellan.mcace.protocol.generated.BoundedPayloadKind.BOUNDED_PAYLOAD_ARTIFACT_OBSERVATION,
                    sessionId, payload, update.getAggregateRootSha256().toByteArray(), 1L,
                    envelopeCodec, sessionKeyPair.getPrivate());
            List<OutboundFrame> result = fragments.stream()
                    .map(frame -> new OutboundFrame(OutboundChannel.PAYLOAD, frame)).toList();
            // startSequence is transfer-local: transfer_id, signature nonce, and update_sequence
            // make successive transfers distinct. State advances only after the platform commits.
            return new PreparedArtifactObservationUpdate(this, nextArtifactObservationSequence + 1L,
                    now, bundle.aggregateRootSha256(), result);
        } catch (BoundedPayloadException exception) {
            throw new EnvelopeException("artifact observation cannot be transferred within protocol limits", exception);
        }
    }

    /**
     * Re-scans exactly the already signed policy scopes. Explicit files additionally require the
     * caller's current, connection-bound authorization; the set cannot expand the signed policy.
     */
    public synchronized PreparedArtifactObservationUpdate prepareRescannedArtifactObservationUpdate(
            Path minecraftRoot, Set<String> consentedExplicitFiles)
            throws EnvelopeException, IntegrityScanException {
        return prepareRescannedArtifactObservationUpdate(
                minecraftRoot, consentedExplicitFiles, IntegrityScanCancellation.NONE);
    }

    public synchronized PreparedArtifactObservationUpdate prepareRescannedArtifactObservationUpdate(
            Path minecraftRoot, Set<String> consentedExplicitFiles,
            IntegrityScanCancellation cancellation)
            throws EnvelopeException, IntegrityScanException {
        if (verifiedPolicy == null) {
            throw new EnvelopeException("artifact observations require a verified policy");
        }
        Objects.requireNonNull(cancellation, "cancellation").check();
        ClientIntegrityBundle bundle = new PolicyDrivenIntegrityCollector(clock)
                .collect(Objects.requireNonNull(minecraftRoot, "minecraftRoot"), verifiedPolicy.policy(),
                        Objects.requireNonNull(consentedExplicitFiles, "consentedExplicitFiles"), cancellation);
        cancellation.check();
        return prepareArtifactObservationUpdate(bundle,
                new ArtifactObservationCollector().collect(
                        minecraftRoot, verifiedPolicy.policy(), bundle, cancellation));
    }

    /** Commits a prepared update exactly once after every fragment was accepted by the transport. */
    public synchronized void commitArtifactObservationUpdate(PreparedArtifactObservationUpdate prepared)
            throws EnvelopeException {
        Objects.requireNonNull(prepared, "prepared");
        if (prepared.engine != this || prepared.committed
                || prepared.sequence != nextArtifactObservationSequence + 1L
                || prepared.observedAtEpochMs < lastArtifactObservationAtEpochMs) {
            throw new EnvelopeException("artifact observation preparation is stale or already committed");
        }
        prepared.committed = true;
        nextArtifactObservationSequence = prepared.sequence;
        lastArtifactObservationAtEpochMs = prepared.observedAtEpochMs;
        lastArtifactObservationAggregateRoot = prepared.aggregateRoot.clone();
    }

    /** Verifies a server-signed ACK and binds it to one still-pending request in this session. */
    public synchronized VerifiedEvidenceAck receiveEvidenceAck(byte[] encodedFrame) throws EnvelopeException {
        SignedEnvelope envelope = verifyEvidenceServerFrame(encodedFrame, PacketType.EVIDENCE_ACK);
        try {
            EvidenceAck ack = EvidenceAck.parseFrom(envelope.getPayload());
            VerifiedEvidenceRequest request = pendingEvidenceRequests.get(ack.getRequestId());
            Long finalSequence = pendingEvidenceFinalSequences.get(ack.getRequestId());
            long previousServerSequence = pendingEvidenceServerSequences.getOrDefault(ack.getRequestId(), 0L);
            boolean acceptedBegin = ack.getStatus() == EvidenceAckStatus.EVIDENCE_ACK_ACCEPTED
                    && ack.getAcknowledgedPacketType() == PacketType.EVIDENCE_BEGIN
                    && ack.getTransportSequence() == 1L;
            boolean completeFinal = ack.getStatus() == EvidenceAckStatus.EVIDENCE_ACK_COMPLETE
                    && (ack.getAcknowledgedPacketType() == PacketType.EVIDENCE_COMMIT
                        || ack.getAcknowledgedPacketType() == PacketType.EVIDENCE_RESPONSE)
                    && finalSequence != null
                    && ack.getTransportSequence() == finalSequence;
            if (request == null
                    || !request.evidenceId().equals(ack.getEvidenceId())
                    || ack.getRequestId().isBlank()
                    || !strictlyIncreasingEvidenceSequence(ack.getTransportSequence(), previousServerSequence)
                    || ack.getAcknowledgedPacketType() == PacketType.PACKET_TYPE_UNSPECIFIED
                    || ack.getAcknowledgedPacketType() == PacketType.UNRECOGNIZED
                    || ack.getStatus() == EvidenceAckStatus.EVIDENCE_ACK_STATUS_UNSPECIFIED
                    || ack.getStatus() == EvidenceAckStatus.UNRECOGNIZED
                    || (!acceptedBegin && !completeFinal)) {
                throw new EnvelopeException("evidence ACK is not bound to a pending request");
            }
            pendingEvidenceServerSequences.put(ack.getRequestId(), ack.getTransportSequence());
            return new VerifiedEvidenceAck(request, ack);
        } catch (InvalidProtocolBufferException exception) {
            throw new EnvelopeException("malformed evidence ACK", exception);
        }
    }

    /** Verifies a server-signed ERROR and binds it to one still-pending request in this session. */
    public synchronized VerifiedEvidenceError receiveEvidenceError(byte[] encodedFrame) throws EnvelopeException {
        SignedEnvelope envelope = verifyEvidenceServerFrame(encodedFrame, PacketType.EVIDENCE_ERROR);
        try {
            EvidenceError error = EvidenceError.parseFrom(envelope.getPayload());
            VerifiedEvidenceRequest request = pendingEvidenceRequests.get(error.getRequestId());
            long previousServerSequence = pendingEvidenceServerSequences.getOrDefault(error.getRequestId(), 0L);
            if (request == null
                    || !request.evidenceId().equals(error.getEvidenceId())
                    || error.getRequestId().isBlank()
                    || !strictlyIncreasingEvidenceSequence(error.getTransportSequence(), previousServerSequence)
                    || error.getRejectedPacketType() == PacketType.PACKET_TYPE_UNSPECIFIED
                    || error.getRejectedPacketType() == PacketType.UNRECOGNIZED
                    || error.getCode() == EvidenceErrorCode.EVIDENCE_ERROR_CODE_UNSPECIFIED
                    || error.getCode() == EvidenceErrorCode.UNRECOGNIZED) {
                throw new EnvelopeException("evidence ERROR is not bound to a pending request");
            }
            pendingEvidenceServerSequences.put(error.getRequestId(), error.getTransportSequence());
            return new VerifiedEvidenceError(request, error);
        } catch (InvalidProtocolBufferException exception) {
            throw new EnvelopeException("malformed evidence ERROR", exception);
        }
    }

    /**
     * Verifies one server-signed evidence request after authentication. The envelope session id,
     * signature, nonce, and timestamp are checked before the request is exposed to the platform
     * adapter. {@code evidence_id} is the protocol request id and is one-shot within this session.
     * The protocol verifier rejects an expired request before it reaches the adapter. A request
     * that expires while waiting for consent remains locally represented and can produce the
     * explicit EXPIRED, zero-content outcome; it can never be used to capture content.
     */
    public synchronized VerifiedEvidenceRequest receiveEvidenceRequest(byte[] encodedFrame)
            throws EnvelopeException {
        if (!heartbeatReady() || sessionId == null || !authenticationResultReceived) {
            throw new EnvelopeException("evidence request requires an authenticated session");
        }
        EvidenceRequestVerifier.VerifiedRequest verified = evidenceRequestVerifier.accept(
                encodedFrame,
                envelopeCodec,
                serverPublicKey,
                replayGuard,
                sessionId,
                playerId.toString());
        EvidenceRequest request = verified.request();
        VerifiedEvidenceRequest accepted = new VerifiedEvidenceRequest(
                request.getEvidenceId(),
                request.getRequestId(),
                request.getPlayerId(),
                request.getType(),
                request.getCaptureScope(),
                request.getExpiresAtEpochMs(),
                request.getCaseId(),
                request.getRawContentRetained(),
                request.getRetentionSeconds(),
                request.getRetentionPolicyId(),
                request.getRetentionPurpose());
        pendingEvidenceRequests.values().removeIf(value -> value.expiredAt(clock.millis()));
        pendingEvidenceFinalSequences.keySet().retainAll(pendingEvidenceRequests.keySet());
        pendingEvidenceServerSequences.keySet().retainAll(pendingEvidenceRequests.keySet());
        if (pendingEvidenceRequests.containsKey(accepted.requestId())) {
            throw new EnvelopeException("evidence request id is already active");
        }
        if (pendingEvidenceRequests.size() >= MAX_PENDING_EVIDENCE_REQUESTS) {
            throw new EnvelopeException("too many pending evidence requests");
        }
        pendingEvidenceRequests.put(accepted.requestId(), accepted);
        pendingEvidenceServerSequences.put(accepted.requestId(), 0L);
        return accepted;
    }

    /**
     * Creates a signed, zero-content outcome. Declines, expiry, unsupported scopes, and failures
     * are outcomes only; they are never represented as evidence content or a risk signal.
     */
    public synchronized List<OutboundFrame> createEvidenceResponseFrames(
            VerifiedEvidenceRequest request, EvidenceCollectionStatus status) throws EnvelopeException {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(status, "status");
        if (status == EvidenceCollectionStatus.EVIDENCE_COLLECTION_STATUS_UNSPECIFIED
                || status == EvidenceCollectionStatus.UNRECOGNIZED
                || status == EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED) {
            throw new EnvelopeException("evidence response status must be a non-content outcome");
        }
        requirePendingEvidenceRequest(request);
        EvidenceResponse response = EvidenceResponse.newBuilder()
                .setEvidenceId(request.evidenceId())
                .setType(request.type())
                .setCapturedAtEpochMs(clock.millis())
                .setCollectionStatus(status.name())
                .setCaptureScope(request.captureScope())
                .setCollectionStatusCode(status)
                .setRequestId(request.requestId())
                .setPlayerId(request.playerId())
                .build();
        EvidenceTransferLimits.validateResponse(response, request.toProto(), clock.millis());
        pendingEvidenceFinalSequences.put(request.requestId(), 1L);
        return List.of(new OutboundFrame(
                OutboundChannel.PAYLOAD,
                signedFrame(PacketType.EVIDENCE_RESPONSE, response.toByteArray())));
    }

    /**
     * Creates the signed BEGIN/CHUNK/COMMIT sequence for one consented Minecraft render frame.
     * Encoding is supplied by the platform adapter; this method only applies the shared byte,
     * chunk, pixel, hash, and signed-session bounds.
     */
    public synchronized List<OutboundFrame> createEvidenceTransferFrames(
            VerifiedEvidenceRequest request,
            EvidenceConsentGrant consent,
            long capturedAtEpochMs,
            int widthPixels,
            int heightPixels,
            byte[] encodedContent) throws EnvelopeException {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(consent, "consent");
        Objects.requireNonNull(encodedContent, "encodedContent");
        requirePendingEvidenceRequest(request);
        if (consent.engine != this || consent.consumed || !request.equals(consent.request)) {
            throw new EnvelopeException("evidence consent is not valid for this request");
        }
        consent.consumed = true;
        if (clock.millis() >= request.expiresAtEpochMs()) {
            throw new EnvelopeException("evidence request expired before capture completed");
        }
        if (request.type() != EvidenceType.SCREENSHOT
                || request.captureScope() != EvidenceCaptureScope.GAME_RENDER_FRAME) {
            throw new EnvelopeException("only GAME_RENDER_FRAME screenshots are supported");
        }
        if (capturedAtEpochMs <= 0 || capturedAtEpochMs > clock.millis() + ProtocolConstants.DEFAULT_CLOCK_SKEW.toMillis()) {
            throw new EnvelopeException("invalid evidence capture timestamp");
        }
        if (widthPixels <= 0 || heightPixels <= 0
                || (long) widthPixels * heightPixels > ProtocolConstants.MAX_EVIDENCE_PIXELS) {
            throw new EnvelopeException("evidence frame exceeds pixel bound");
        }
        ChunkedEvidencePayload chunked;
        try {
            chunked = new EvidencePayloadChunker().chunk(encodedContent,
                    EvidencePayloadChunker.Limits.protocolDefaults());
        } catch (IllegalArgumentException exception) {
            throw new EnvelopeException("evidence frame exceeds byte or chunk bounds", exception);
        }
        EvidenceBegin begin = EvidenceBegin.newBuilder()
                .setEvidenceId(request.evidenceId())
                .setType(request.type())
                .setCaptureScope(request.captureScope())
                .setCollectionStatus(EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED)
                .setCapturedAtEpochMs(capturedAtEpochMs)
                .setTotalBytes(chunked.totalBytes())
                .setTotalChunks(chunked.chunks().size())
                .setWidthPixels(widthPixels)
                .setHeightPixels(heightPixels)
                .setContentSha256(ByteString.copyFrom(chunked.sha256()))
                .setMerkleRootSha256(ByteString.copyFrom(chunked.merkleRoot()))
                .setRequestId(request.requestId())
                .setPlayerId(request.playerId())
                .setTransportSequence(1L)
                .build();
        EvidenceTransferLimits.validateBegin(begin);
        try {
            List<OutboundFrame> frames = new ArrayList<>(chunked.chunks().size() + 2);
            frames.add(new OutboundFrame(
                    OutboundChannel.PAYLOAD,
                    signedFrame(PacketType.EVIDENCE_BEGIN, begin.toByteArray())));
            long transportSequence = 2L;
            for (EvidencePayloadChunk payloadChunk : chunked.chunks()) {
                EvidenceChunk chunk = EvidenceChunk.newBuilder()
                        .setEvidenceId(request.evidenceId())
                        .setChunkIndex(payloadChunk.index())
                        .setContent(ByteString.copyFrom(payloadChunk.content()))
                        .setChunkSha256(ByteString.copyFrom(payloadChunk.sha256()))
                        .setRequestId(request.requestId())
                        .setPlayerId(request.playerId())
                        .setTransportSequence(transportSequence++)
                        .build();
                EvidenceTransferLimits.validateChunk(chunk, begin);
                frames.add(new OutboundFrame(
                        OutboundChannel.PAYLOAD,
                        signedFrame(PacketType.EVIDENCE_CHUNK, chunk.toByteArray())));
            }
            EvidenceCommit commit = EvidenceCommit.newBuilder()
                    .setEvidenceId(request.evidenceId())
                    .setTotalBytes(chunked.totalBytes())
                    .setTotalChunks(chunked.chunks().size())
                    .setContentSha256(ByteString.copyFrom(chunked.sha256()))
                    .setMerkleRootSha256(ByteString.copyFrom(chunked.merkleRoot()))
                    .setCollectionStatus(EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED)
                    .setRequestId(request.requestId())
                    .setPlayerId(request.playerId())
                    .setTransportSequence(transportSequence)
                    .build();
            EvidenceTransferLimits.validateCommit(commit, begin);
            pendingEvidenceFinalSequences.put(request.requestId(), transportSequence);
            frames.add(new OutboundFrame(
                    OutboundChannel.PAYLOAD,
                    signedFrame(PacketType.EVIDENCE_COMMIT, commit.toByteArray())));
            return List.copyOf(frames);
        } finally {
            chunked.clear();
        }
    }

    /** Issues a one-shot in-memory grant only after the platform's visible consent UI accepted. */
    public synchronized EvidenceConsentGrant grantEvidenceConsent(VerifiedEvidenceRequest request)
            throws EnvelopeException {
        requirePendingEvidenceRequest(Objects.requireNonNull(request, "request"));
        if (request.expiredAt(clock.millis())) {
            throw new EnvelopeException("evidence request expired before consent");
        }
        if (request.captureScope() != EvidenceCaptureScope.GAME_RENDER_FRAME) {
            throw new EnvelopeException("consent is unavailable for this capture scope");
        }
        if (!issuedEvidenceConsents.add(request.requestId())) {
            throw new EnvelopeException("evidence consent was already issued for this request");
        }
        return new EvidenceConsentGrant(this, request);
    }

    /** Removes a request only after its final frames have been sent successfully. */
    public synchronized void completeEvidenceRequest(VerifiedEvidenceRequest request)
            throws EnvelopeException {
        requirePendingEvidenceRequest(request);
        pendingEvidenceRequests.remove(request.requestId());
        issuedEvidenceConsents.remove(request.requestId());
        pendingEvidenceFinalSequences.remove(request.requestId());
        pendingEvidenceServerSequences.remove(request.requestId());
    }

    /** Cancels a pending request without producing content; used on disconnect or send failure. */
    public synchronized void cancelEvidenceRequest(VerifiedEvidenceRequest request) {
        if (request != null && request.equals(pendingEvidenceRequests.get(request.requestId()))) {
            pendingEvidenceRequests.remove(request.requestId());
            issuedEvidenceConsents.remove(request.requestId());
            pendingEvidenceFinalSequences.remove(request.requestId());
            pendingEvidenceServerSequences.remove(request.requestId());
        }
    }

    private void requirePendingEvidenceRequest(VerifiedEvidenceRequest request) throws EnvelopeException {
        if (sessionId == null || !heartbeatReady()
                || !request.equals(pendingEvidenceRequests.get(request.requestId()))) {
            throw new EnvelopeException("evidence request is not active for this session");
        }
    }

    private SignedEnvelope verifyEvidenceServerFrame(byte[] encodedFrame, PacketType expectedType)
            throws EnvelopeException {
        if (!heartbeatReady() || sessionId == null) {
            throw new EnvelopeException("evidence acknowledgement requires an authenticated session");
        }
        Objects.requireNonNull(encodedFrame, "encodedFrame");
        try {
            BoundedPayloadTransferLimits.validateFrameBytes(encodedFrame.length);
        } catch (BoundedPayloadException exception) {
            throw new EnvelopeException("evidence acknowledgement exceeds raw frame budget", exception);
        }
        SignedEnvelope envelope = envelopeCodec.parse(encodedFrame);
        envelopeCodec.verify(envelope, serverPublicKey, replayGuard);
        if (envelope.getHeader().getPacketType() != expectedType
                || !sessionId.equals(envelope.getHeader().getSessionId())) {
            throw new EnvelopeException("evidence acknowledgement packet or session mismatch");
        }
        return envelope;
    }

    private static boolean strictlyIncreasingEvidenceSequence(long candidate, long previous) {
        return candidate > 0L && previous >= 0L && candidate > previous;
    }

    /** A request after server-envelope verification and authenticated-session binding. */
    public record VerifiedEvidenceRequest(
            String evidenceId,
            String requestId,
            String playerId,
            EvidenceType type,
            EvidenceCaptureScope captureScope,
            long expiresAtEpochMs,
            String caseId,
            boolean rawContentRetained,
            long retentionSeconds,
            String retentionPolicyId,
            String retentionPurpose) {
        public VerifiedEvidenceRequest(
                String evidenceId,
                String requestId,
                String playerId,
                EvidenceType type,
                EvidenceCaptureScope captureScope,
                long expiresAtEpochMs,
                String caseId) {
            this(evidenceId, requestId, playerId, type, captureScope, expiresAtEpochMs, caseId,
                    false, 0L, "", "");
        }

        public VerifiedEvidenceRequest {
            Objects.requireNonNull(evidenceId, "evidenceId");
            Objects.requireNonNull(requestId, "requestId");
            Objects.requireNonNull(playerId, "playerId");
            Objects.requireNonNull(type, "type");
            Objects.requireNonNull(captureScope, "captureScope");
            Objects.requireNonNull(caseId, "caseId");
            Objects.requireNonNull(retentionPolicyId, "retentionPolicyId");
            Objects.requireNonNull(retentionPurpose, "retentionPurpose");
        }

        public boolean expiredAt(long nowEpochMs) {
            return nowEpochMs >= expiresAtEpochMs;
        }

        public EvidenceRequest toProto() {
            return EvidenceRequest.newBuilder()
                    .setEvidenceId(evidenceId)
                    .setType(type)
                    .setCaptureScope(captureScope)
                    .setExpiresAtEpochMs(expiresAtEpochMs)
                    .setCaseId(caseId)
                    .setRequestId(requestId)
                    .setPlayerId(playerId)
                    .setRawContentRetained(rawContentRetained)
                    .setRetentionSeconds(Math.toIntExact(retentionSeconds))
                    .setRetentionPolicyId(retentionPolicyId)
                    .setRetentionPurpose(retentionPurpose)
                    .build();
        }
    }

    /** Opaque one-shot bridge from an explicit UI decision to one capture transfer. */
    public static final class EvidenceConsentGrant {
        private final ClientHandshakeEngine engine;
        private final VerifiedEvidenceRequest request;
        private boolean consumed;

        private EvidenceConsentGrant(ClientHandshakeEngine engine, VerifiedEvidenceRequest request) {
            this.engine = engine;
            this.request = request;
        }
    }

    public record VerifiedEvidenceAck(VerifiedEvidenceRequest request, EvidenceAck ack) {
        public VerifiedEvidenceAck {
            Objects.requireNonNull(request, "request");
            Objects.requireNonNull(ack, "ack");
        }
    }

    public record VerifiedEvidenceError(VerifiedEvidenceRequest request, EvidenceError error) {
        public VerifiedEvidenceError {
            Objects.requireNonNull(request, "request");
            Objects.requireNonNull(error, "error");
        }
    }

    private AuthRequest buildAuthentication(
            ClientIntegrityBundle bundle,
            VerifiedPolicy policy,
            List<ArtifactObservation> observations)
            throws EnvelopeException {
        ScopeIntegrityManifest modsScope = bundle.scope("mods").orElseThrow(
                () -> new EnvelopeException("policy result does not contain mods scope"));
        Map<ManifestEntryKey, ArtifactObservation> enrichments = validateObservations(bundle, observations);
        List<ModEntry> mods = new ArrayList<>(modsScope.entries().size());
        for (IntegrityEntry entry : modsScope.entries()) {
            ArtifactObservation metadata = enrichments.get(new ManifestEntryKey(
                    modsScope.scope(), entry.relativePath(), entry.sha256Hex()));
            mods.add(ModEntry.newBuilder()
                    // Legacy callers have no bounded Fabric metadata enrichment.  They remain
                    // compatible but deliberately cannot be matched as a mod id/version rule.
                    .setId(metadata == null ? "unknown" : metadata.identifier())
                    .setVersion(metadata == null ? "unknown" : metadata.version())
                    .setFilename(entry.relativePath())
                    .setFileSize(entry.fileSize())
                    .setSha256(ByteString.copyFrom(entry.sha256()))
                    .build());
        }
        byte[] environmentHash = digest(
                minecraftVersion.getBytes(StandardCharsets.UTF_8),
                loader.name().getBytes(StandardCharsets.UTF_8),
                bundle.aggregateRootSha256(),
                policy.policySha256());
        String clientId = HexFormat.of().formatHex(digest(sessionKeyPair.getPublic().getEncoded())).substring(0, 32);
        AuthRequest.Builder request = AuthRequest.newBuilder()
                .setPlayerUuid(playerId.toString())
                .setClientId(clientId)
                .setBuildId(buildId)
                .addAllMods(mods)
                .setManifestRootSha256(ByteString.copyFrom(modsScope.rootSha256()))
                .setEnvironmentSha256(ByteString.copyFrom(environmentHash))
                .setPolicySha256(ByteString.copyFrom(policy.policySha256()))
                .setPolicySequence(policy.policy().getSequence());
        for (ScopeIntegrityManifest scope : bundle.scopes()) {
            IntegrityScopeManifest.Builder manifest = IntegrityScopeManifest.newBuilder()
                    .setScope(scope.scope())
                    .setRelativeRoot(scope.relativeRoot())
                    .setPresent(scope.present())
                    .setEntryCount(scope.entries().size())
                    .setRootSha256(ByteString.copyFrom(scope.rootSha256()));
            for (IntegrityEntry entry : scope.entries()) {
                manifest.addEntries(FileEntry.newBuilder()
                        .setRelativePath(entry.relativePath())
                        .setFileSize(entry.fileSize())
                        .setSha256(ByteString.copyFrom(entry.sha256())));
            }
            request.addScopeManifests(manifest);
        }
        return request.build();
    }

    private static Map<ManifestEntryKey, ArtifactObservation> validateObservations(
            ClientIntegrityBundle bundle, List<ArtifactObservation> observations) throws EnvelopeException {
        Map<String, ArtifactType> typeByScope = new HashMap<>();
        Set<ManifestEntryKey> authorized = new HashSet<>();
        for (ScopeIntegrityManifest scope : bundle.scopes()) {
            ArtifactType type = artifactType(scope.relativeRoot());
            if (type == null) {
                continue;
            }
            typeByScope.put(scope.scope(), type);
            for (IntegrityEntry entry : scope.entries()) {
                authorized.add(new ManifestEntryKey(scope.scope(), entry.relativePath(), entry.sha256Hex()));
            }
        }
        Map<ManifestEntryKey, ArtifactObservation> accepted = new HashMap<>();
        for (ArtifactObservation observation : observations) {
            if (observation.origin() != ObservationOrigin.CLIENT_REPORTED
                    || observation.confidence() != Confidence.LOW
                    || observation.foundationSecurity()) {
                throw new EnvelopeException("authentication observations must be low-confidence client reports");
            }
            String scope = observation.metadata().get("scope");
            String path = observation.metadata().get("artifact_path");
            if (scope == null || path == null || observation.sha256() == null) {
                throw new EnvelopeException("authentication observation is missing bundle provenance");
            }
            ManifestEntryKey key = new ManifestEntryKey(scope, path, observation.sha256());
            if (typeByScope.get(scope) != observation.type() || !authorized.contains(key)) {
                throw new EnvelopeException("authentication observation is outside the authorized integrity bundle");
            }
            if (accepted.putIfAbsent(key, observation) != null) {
                throw new EnvelopeException("authentication observation duplicates a manifest entry");
            }
        }
        return Map.copyOf(accepted);
    }

    private static ArtifactType artifactType(String relativeRoot) {
        return switch (relativeRoot) {
            case "mods" -> ArtifactType.MOD;
            case "resourcepacks" -> ArtifactType.RESOURCE_PACK;
            case "shaderpacks" -> ArtifactType.SHADER_PACK;
            default -> null;
        };
    }

    private record ManifestEntryKey(String scope, String path, String sha256) {
        private ManifestEntryKey {
            Objects.requireNonNull(scope, "scope");
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(sha256, "sha256");
        }
    }

    private byte[] signedFrame(PacketType packetType, byte[] payload) throws EnvelopeException {
        byte[] frame = envelopeCodec.sign(packetType, sessionId, payload, sessionKeyPair.getPrivate()).toByteArray();
        try {
            BoundedPayloadTransferLimits.validateFrameBytes(frame.length);
            return frame;
        } catch (BoundedPayloadException exception) {
            if (packetType == PacketType.AUTH_REQUEST) {
                return frame;
            }
            throw new EnvelopeException("MCAce control frame exceeds plugin-message budget", exception);
        }
    }

    private void requireFederationAuthenticated() throws EnvelopeException {
        if (sessionId == null || acceptedHello == null || acceptedHeartbeatBinding == null
                || !authenticationResultReceived) {
            throw new EnvelopeException("federation requires accepted local authentication");
        }
    }

    private void validateFederationRequestBinding(
            com.ellan.mcace.protocol.generated.FederationConsentRequest request) throws EnvelopeException {
        if (request.getSchemaVersion() != ProtocolConstants.FEDERATION_SCHEMA_VERSION
                || !request.getSourceNetworkId().equals(acceptedHello.getServerId())
                || !request.getPlayerUuid().equals(playerId.toString())
                || !request.getLocalAuthenticatedSessionId().equals(sessionId)
                || request.getClientPublicKeySha256().size() != 32
                || !MessageDigest.isEqual(request.getClientPublicKeySha256().toByteArray(),
                        digest(sessionKeyPair.getPublic().getEncoded()))
                || request.getSourceKeyIdSha256().size() != 32
                || !MessageDigest.isEqual(request.getSourceKeyIdSha256().toByteArray(),
                        digest(serverPublicKey.getEncoded()))
                || request.getTargetKeyIdSha256().size() != 32
                || request.getAssertionNonce().size() != ProtocolConstants.NONCE_BYTES
                || request.getPolicySha256().size() != 32
                || !request.getPolicyVersion().equals(verifiedPolicy.policy().getPolicyVersion())
                || !MessageDigest.isEqual(request.getPolicySha256().toByteArray(), verifiedPolicy.policySha256())
                || request.getExpiresAtEpochMs() <= clock.millis()
                || request.getExpiresAtEpochMs() - clock.millis()
                        > ProtocolConstants.MAX_FEDERATION_ASSERTION_TTL.toMillis()
                || invalidFederationText(request.getTargetNetworkId(), ProtocolConstants.MAX_FEDERATION_ID_CHARS)
                || invalidFederationText(request.getAssertionId(), ProtocolConstants.MAX_FEDERATION_ID_CHARS)
                || invalidFederationText(request.getDisclosure(), ProtocolConstants.MAX_FEDERATION_DISCLOSURE_CHARS)) {
            throw new EnvelopeException("federation consent request does not bind this live session");
        }
    }

    private static boolean invalidFederationText(String value, int maximumLength) {
        return value == null || value.isBlank() || value.length() > maximumLength
                || value.codePoints().anyMatch(Character::isISOControl);
    }

    /** A verified server request; UI must still receive an explicit Allow once action. */
    public record VerifiedFederationConsentRequest(
            com.ellan.mcace.protocol.generated.FederationConsentRequest request) {
        public VerifiedFederationConsentRequest {
            Objects.requireNonNull(request, "request");
        }
    }

    public enum OutboundChannel {
        HANDSHAKE,
        PAYLOAD
    }

    /** An immutable frame restricted to one of the two MCAce client transport channels. */
    public record OutboundFrame(OutboundChannel channel, byte[] data) {
        public OutboundFrame {
            Objects.requireNonNull(channel, "channel");
            Objects.requireNonNull(data, "data");
            if (data.length == 0 || data.length > ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES) {
                throw new IllegalArgumentException("outbound frame exceeds plugin-message budget");
            }
            data = data.clone();
        }

        @Override
        public byte[] data() {
            return data.clone();
        }

        /** Clears the frame owned by the client after send, cancellation, or a channel failure. */
        public void clear() {
            java.util.Arrays.fill(data, (byte) 0);
        }
    }

    /** Opaque one-shot state transition for an optional complete post-auth snapshot. */
    public static final class PreparedArtifactObservationUpdate {
        private final ClientHandshakeEngine engine;
        private final long sequence;
        private final long observedAtEpochMs;
        private final byte[] aggregateRoot;
        private final List<OutboundFrame> frames;
        private boolean committed;

        private PreparedArtifactObservationUpdate(ClientHandshakeEngine engine, long sequence,
                long observedAtEpochMs, byte[] aggregateRoot, List<OutboundFrame> frames) {
            this.engine = engine;
            this.sequence = sequence;
            this.observedAtEpochMs = observedAtEpochMs;
            this.aggregateRoot = aggregateRoot.clone();
            this.frames = List.copyOf(frames);
        }

        public List<OutboundFrame> frames() { return frames; }
    }

    /** Immutable hash/policy values captured from the signed authentication request. */
    private record HeartbeatBinding(
            byte[] manifestRoot,
            long policySequence,
            byte[] policyHash,
            byte[] aggregateRoot,
            String currentServer) {
        private HeartbeatBinding {
            manifestRoot = requiredSha256(manifestRoot, "manifest root");
            if (policySequence == 0L) {
                throw new IllegalArgumentException("policy sequence must be positive");
            }
            policyHash = requiredSha256(policyHash, "policy hash");
            aggregateRoot = requiredSha256(aggregateRoot, "aggregate root");
            currentServer = requireText(currentServer, "current server");
            if (currentServer.length() > ProtocolConstants.MAX_HEARTBEAT_CURRENT_SERVER_CHARS
                    || currentServer.chars().anyMatch(Character::isISOControl)) {
                throw new IllegalArgumentException("current server exceeds heartbeat privacy budget");
            }
        }

        @Override
        public byte[] manifestRoot() {
            return manifestRoot.clone();
        }

        @Override
        public byte[] policyHash() {
            return policyHash.clone();
        }

        @Override
        public byte[] aggregateRoot() {
            return aggregateRoot.clone();
        }
    }

    private static byte[] requiredSha256(byte[] value, String name) {
        Objects.requireNonNull(value, name);
        if (value.length != 32) {
            throw new IllegalArgumentException(name + " must be SHA-256");
        }
        return value.clone();
    }

    private static byte[] digest(byte[]... values) throws EnvelopeException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (byte[] value : values) {
                digest.update(value);
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException exception) {
            throw new EnvelopeException("SHA-256 is unavailable", exception);
        }
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
