package com.ellan.mcace.core.session;

import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.core.evidence.EvidenceContentStore;
import com.ellan.mcace.core.evidence.EvidenceAuditSink;
import com.ellan.mcace.core.evidence.EvidenceIngressResult;
import com.ellan.mcace.core.evidence.EvidenceRequestRuntime;
import com.ellan.mcace.core.evidence.EvidenceRequestSpec;
import com.ellan.mcace.core.federation.FederationSubject;
import com.ellan.mcace.core.policy.SignedPolicyProvider;
import com.ellan.mcace.core.persistence.ObservationOrigin;
import com.ellan.mcace.core.persistence.RiskEventAuditRecord;
import com.ellan.mcace.core.persistence.SecurityAuditSink;
import com.ellan.mcace.core.persistence.SecurityPersistenceException;
import com.ellan.mcace.core.persistence.SessionAuditRecord;
import com.ellan.mcace.core.risk.ObservedRiskEvent;
import com.ellan.mcace.core.risk.RiskAssessment;
import com.ellan.mcace.core.risk.RiskEngine;
import com.ellan.mcace.core.risk.RiskEventType;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.AuthRequest;
import com.ellan.mcace.protocol.generated.AuthResult;
import com.ellan.mcace.protocol.generated.ArtifactObservationUpdate;
import com.ellan.mcace.protocol.generated.BoundedPayloadKind;
import com.ellan.mcace.protocol.generated.ClientHello;
import com.ellan.mcace.protocol.generated.FileEntry;
import com.ellan.mcace.protocol.generated.IntegrityScopeManifest;
import com.ellan.mcace.protocol.generated.IntegrityScopeRule;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.ServerHello;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.protocol.integrity.IntegrityDigests;
import com.ellan.mcace.protocol.heartbeat.HeartbeatException;
import com.ellan.mcace.protocol.heartbeat.HeartbeatHealth;
import com.ellan.mcace.protocol.heartbeat.HeartbeatSessionStateMachine;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyException;
import com.ellan.mcace.protocol.transport.BoundedPayloadException;
import com.ellan.mcace.protocol.transport.BoundedPayloadTransferLimits;
import com.ellan.mcace.protocol.transport.BoundedPayloadTransferReceiver;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

public final class ServerHandshakeCoordinator {
    private final Clock clock;
    private final SecureRandom secureRandom;
    private final KeyPair serverKeyPair;
    private final EnvelopeCodec envelopeCodec;
    private final NonceReplayGuard replayGuard;
    private final RiskEngine riskEngine;
    private final InMemoryMCAceApi api;
    private final Duration timeout;
    private final SignedPolicyProvider policyProvider;
    private final SecurityAuditSink auditSink;
    private final Consumer<Exception> persistenceFailureHandler;
    private final Consumer<AuthenticatedManifest> authenticatedManifestHandler;
    /** Optional post-auth complete-snapshot audit path. Never feeds admission or risk. */
    private final Consumer<AuthenticatedManifest> artifactObservationUpdateHandler;
    private final EvidenceRequestRuntime evidenceRuntime;
    private final Map<UUID, SessionContext> sessions = new HashMap<>();

    public ServerHandshakeCoordinator(
            Clock clock,
            SecureRandom secureRandom,
            KeyPair serverKeyPair,
            RiskEngine riskEngine,
            InMemoryMCAceApi api,
            Duration timeout,
            SignedPolicyProvider policyProvider) {
        this(clock, secureRandom, serverKeyPair, riskEngine, api, timeout, policyProvider,
                SecurityAuditSink.noop(), ignored -> { }, ignored -> { }, ignored -> { },
                EvidenceContentStore.discard(), EvidenceAuditSink.noop());
    }

    /** Observation-only callback after a client has completed the authenticated manifest exchange. */
    public ServerHandshakeCoordinator(
            Clock clock,
            SecureRandom secureRandom,
            KeyPair serverKeyPair,
            RiskEngine riskEngine,
            InMemoryMCAceApi api,
            Duration timeout,
            SignedPolicyProvider policyProvider,
            Consumer<AuthenticatedManifest> authenticatedManifestHandler) {
        this(clock, secureRandom, serverKeyPair, riskEngine, api, timeout, policyProvider,
                SecurityAuditSink.noop(), ignored -> { }, authenticatedManifestHandler, ignored -> { },
                EvidenceContentStore.discard(), EvidenceAuditSink.noop());
    }

    public ServerHandshakeCoordinator(
            Clock clock,
            SecureRandom secureRandom,
            KeyPair serverKeyPair,
            RiskEngine riskEngine,
            InMemoryMCAceApi api,
            Duration timeout,
            SignedPolicyProvider policyProvider,
            SecurityAuditSink auditSink,
            Consumer<Exception> persistenceFailureHandler) {
        this(clock, secureRandom, serverKeyPair, riskEngine, api, timeout, policyProvider, auditSink,
                persistenceFailureHandler, ignored -> { }, ignored -> { },
                EvidenceContentStore.discard(), EvidenceAuditSink.noop());
    }

    public ServerHandshakeCoordinator(
            Clock clock,
            SecureRandom secureRandom,
            KeyPair serverKeyPair,
            RiskEngine riskEngine,
            InMemoryMCAceApi api,
            Duration timeout,
            SignedPolicyProvider policyProvider,
            SecurityAuditSink auditSink,
            Consumer<Exception> persistenceFailureHandler,
            Consumer<AuthenticatedManifest> authenticatedManifestHandler) {
        this(clock, secureRandom, serverKeyPair, riskEngine, api, timeout, policyProvider, auditSink,
                persistenceFailureHandler, authenticatedManifestHandler, ignored -> { },
                EvidenceContentStore.discard(), EvidenceAuditSink.noop());
    }

    public ServerHandshakeCoordinator(
            Clock clock,
            SecureRandom secureRandom,
            KeyPair serverKeyPair,
            RiskEngine riskEngine,
            InMemoryMCAceApi api,
            Duration timeout,
            SignedPolicyProvider policyProvider,
            SecurityAuditSink auditSink,
            Consumer<Exception> persistenceFailureHandler,
            Consumer<AuthenticatedManifest> authenticatedManifestHandler,
            EvidenceContentStore evidenceContentStore,
            EvidenceAuditSink evidenceAuditSink) {
        this(clock, secureRandom, serverKeyPair, riskEngine, api, timeout, policyProvider, auditSink,
                persistenceFailureHandler, authenticatedManifestHandler, ignored -> { }, evidenceContentStore, evidenceAuditSink);
    }

    /**
     * Creates a coordinator with a distinct audit-only post-auth observation handler.
     * The handler is intentionally separate from the initial-manifest callback so dynamic
     * observations cannot accidentally trigger routing or an admission decision.
     */
    public ServerHandshakeCoordinator(
            Clock clock, SecureRandom secureRandom, KeyPair serverKeyPair, RiskEngine riskEngine,
            InMemoryMCAceApi api, Duration timeout, SignedPolicyProvider policyProvider,
            SecurityAuditSink auditSink, Consumer<Exception> persistenceFailureHandler,
            Consumer<AuthenticatedManifest> authenticatedManifestHandler,
            Consumer<AuthenticatedManifest> artifactObservationUpdateHandler,
            EvidenceContentStore evidenceContentStore, EvidenceAuditSink evidenceAuditSink) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
        this.serverKeyPair = Objects.requireNonNull(serverKeyPair, "serverKeyPair");
        this.riskEngine = Objects.requireNonNull(riskEngine, "riskEngine");
        this.api = Objects.requireNonNull(api, "api");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        this.policyProvider = Objects.requireNonNull(policyProvider, "policyProvider");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        this.persistenceFailureHandler = Objects.requireNonNull(
                persistenceFailureHandler, "persistenceFailureHandler");
        this.authenticatedManifestHandler = Objects.requireNonNull(
                authenticatedManifestHandler, "authenticatedManifestHandler");
        this.artifactObservationUpdateHandler = Objects.requireNonNull(
                artifactObservationUpdateHandler, "artifactObservationUpdateHandler");
        Objects.requireNonNull(evidenceContentStore, "evidenceContentStore");
        Objects.requireNonNull(evidenceAuditSink, "evidenceAuditSink");
        if (timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("timeout must be positive");
        }
        this.envelopeCodec = new EnvelopeCodec(
                clock,
                secureRandom,
                ProtocolConstants.MAX_PAYLOAD_BYTES,
                ProtocolConstants.DEFAULT_CLOCK_SKEW);
        this.evidenceRuntime = new EvidenceRequestRuntime(
                clock, secureRandom, serverKeyPair.getPrivate(), auditSink, evidenceAuditSink,
                evidenceContentStore, 4096);
        this.replayGuard = new NonceReplayGuard(clock, ProtocolConstants.DEFAULT_REPLAY_WINDOW);
    }

    public synchronized byte[] begin(UUID playerId) throws EnvelopeException, PolicyException {
        Objects.requireNonNull(playerId, "playerId");
        SignedPolicyDocument policyDocument = policyProvider.current();
        SecurityPolicy policy = PolicyDocuments.verify(
                policyDocument, serverKeyPair.getPublic(), clock, ProtocolConstants.DEFAULT_CLOCK_SKEW);
        byte[] policyDigest = PolicyDocuments.policyDigest(policyDocument);
        byte[] challenge = randomBytes(ProtocolConstants.NONCE_BYTES);
        String sessionId = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(24));
        TrustSession session = new TrustSession(sessionId, playerId, clock.instant());
        session.challengeSent();
        ServerHello hello = ServerHello.newBuilder()
                .setServerId(policy.getServerId())
                .setChallengeNonce(ByteString.copyFrom(challenge))
                .setRequiredLevel(policy.getRequiredLevel())
                .setPolicyVersion(policy.getPolicyVersion())
                .setSignedPolicy(policyDocument)
                .build();
        byte[] frame = envelopeCodec.sign(
                PacketType.SERVER_HELLO, sessionId, hello.toByteArray(), serverKeyPair.getPrivate()).toByteArray();
        try {
            BoundedPayloadTransferLimits.validateFrameBytes(frame.length);
        } catch (BoundedPayloadException exception) {
            throw new EnvelopeException("server hello exceeds proxy frame budget", exception);
        }
        SessionContext context = new SessionContext(session, challenge, clock.instant().plus(timeout), policy, policyDigest);
        sessions.put(playerId, context);
        PlayerSecuritySnapshot snapshot = publish(playerId, TrustLevel.UNKNOWN, AdmissionStatus.VERIFYING, List.of());
        auditSession(context, snapshot);
        return frame;
    }

    public synchronized HandshakeAction receive(UUID playerId, byte[] encodedFrame) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(encodedFrame, "encodedFrame");
        SessionContext context = sessions.get(playerId);
        if (context == null) {
            return violation(playerId, null, RiskEventType.PROTOCOL_VIOLATION);
        }
        if (context.session.stage() != SessionStage.AUTHENTICATED && !clock.instant().isBefore(context.expiresAt)) {
            return timeout(context);
        }

        try {
            // The proxy budget is a raw transport invariant; enforce it before protobuf parsing
            // so unknown packet types and malformed oversized frames cannot allocate first.
            BoundedPayloadTransferLimits.validateFrameBytes(encodedFrame.length);
        } catch (BoundedPayloadException exception) {
            return context.session.stage() == SessionStage.AUTHENTICATED
                    ? heartbeatViolation(context, "oversized transport frame")
                    : violation(playerId, context, RiskEventType.PROTOCOL_VIOLATION);
        }

        try {
            SignedEnvelope envelope = envelopeCodec.parse(encodedFrame);
            // Enforce the proxy budget even when a forged heartbeat names another session.
            if (envelope.hasHeader() && envelope.getHeader().getPacketType() == PacketType.HEARTBEAT) {
                BoundedPayloadTransferLimits.validateFrameBytes(encodedFrame.length);
            }
            if (!envelope.getHeader().getSessionId().equals(context.session.id())) {
                return context.session.stage() == SessionStage.AUTHENTICATED
                        ? heartbeatViolation(context, "heartbeat session binding mismatch")
                        : violation(playerId, context, RiskEventType.PROTOCOL_VIOLATION);
            }
            switch (envelope.getHeader().getPacketType()) {
                case CLIENT_HELLO, AUTH_REQUEST, PAYLOAD_BEGIN, PAYLOAD_CHUNK, PAYLOAD_COMMIT ->
                        BoundedPayloadTransferLimits.validateFrameBytes(encodedFrame.length);
                default -> { }
            }
            return switch (envelope.getHeader().getPacketType()) {
                case CLIENT_HELLO -> receiveClientHello(context, envelope);
                case AUTH_REQUEST -> receiveOrDeferAuthRequest(context, envelope);
                case PAYLOAD_BEGIN, PAYLOAD_CHUNK, PAYLOAD_COMMIT -> receiveBoundedPayload(context, envelope, encodedFrame);
                case HEARTBEAT -> receiveHeartbeat(context, encodedFrame);
                default -> violation(playerId, context, RiskEventType.PROTOCOL_VIOLATION);
            };
        } catch (EnvelopeException | InvalidProtocolBufferException | BoundedPayloadException exception) {
            RiskEventType type = exception.getMessage() != null && exception.getMessage().contains("replayed nonce")
                    ? RiskEventType.AUTH_REPLAY
                    : RiskEventType.PROTOCOL_VIOLATION;
            return context.session.stage() == SessionStage.AUTHENTICATED
                    ? heartbeatViolation(context, "malformed authenticated frame")
                    : violation(playerId, context, type);
        }
    }

    public synchronized List<PlayerSecuritySnapshot> expireTimedOut() {
        List<PlayerSecuritySnapshot> expired = new ArrayList<>();
        for (SessionContext context : sessions.values()) {
            if (!context.terminal && !clock.instant().isBefore(context.expiresAt)) {
                expired.add(timeout(context).snapshot().orElseThrow());
            }
        }
        return List.copyOf(expired);
    }

    /**
     * Checks the session binding used by delayed post-authentication disposition work.  The
     * terminal flag is intentionally not consulted: a successfully authenticated session is
     * terminal for the handshake state machine while remaining valid for its session lifetime.
     */
    public synchronized boolean isCurrentAuthenticatedSession(UUID playerId, String sessionId) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        SessionContext context = sessions.get(playerId);
        return context != null
                && context.session.id().equals(sessionId)
                && context.session.stage() == SessionStage.AUTHENTICATED;
    }

    /**
     * Returns only the current local authenticated-session identifier. This is intentionally a
     * narrower read than federationSubject: it has no trust-level, client-key, risk, admission,
     * federation, or side-effect semantics.
     */
    public synchronized Optional<String> currentAuthenticatedSessionId(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        SessionContext context = sessions.get(playerId);
        if (context == null || context.session.stage() != SessionStage.AUTHENTICATED) {
            return Optional.empty();
        }
        return Optional.of(context.session.id());
    }

    /**
     * Returns the narrow local-authentication binding needed by the opt-in, client-carried
     * federation flow. This is a read-only view: querying it never publishes an SDK snapshot,
     * invokes risk/admission/disposition logic, or extends the lifetime of the session.
     */
    public synchronized Optional<FederationSubject> federationSubject(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        SessionContext context = sessions.get(playerId);
        if (context == null || context.session.stage() != SessionStage.AUTHENTICATED
                || context.session.trustLevel() != TrustLevel.VERIFIED
                || context.session.clientPublicKey().isEmpty()
                || context.authenticatedAt == null) {
            return Optional.empty();
        }
        return Optional.of(new FederationSubject(
                context.session.playerId(),
                context.policy.getServerId(),
                context.session.id(),
                context.session.clientPublicKey().orElseThrow(),
                context.challenge,
                context.policy.getPolicyVersion(),
                context.policyDigest,
                context.authenticatedAt));
    }

    /**
     * Returns only heartbeat health changes. Calling this method never publishes a snapshot,
     * invokes the risk engine, or changes routing/admission state.
     */
    public synchronized List<HeartbeatTransition> pollHeartbeatTransitions() {
        List<HeartbeatTransition> transitions = new ArrayList<>();
        for (SessionContext context : sessions.values()) {
            if (context.heartbeat == null) {
                continue;
            }
            HeartbeatHealth current = context.heartbeat.health();
            if (current != context.lastHeartbeatHealth) {
                transitions.add(new HeartbeatTransition(
                        context.session.playerId(), context.session.id(), context.lastHeartbeatHealth,
                        current, clock.instant()));
                context.lastHeartbeatHealth = current;
            }
        }
        return List.copyOf(transitions);
    }

    /**
     * Produces optional temporary-control transitions without altering player snapshot, risk,
     * admission, or the heartbeat state machine. Callers own all platform action and auditing.
     */
    public synchronized List<HeartbeatMissingTransition> pollHeartbeatMissingTransitions(HeartbeatMissingPolicy policy) {
        Objects.requireNonNull(policy, "policy");
        List<HeartbeatMissingTransition> transitions = new ArrayList<>();
        for (SessionContext context : sessions.values()) {
            if (context.session.stage() != SessionStage.AUTHENTICATED || context.heartbeat == null
                    || context.session.trustLevel() != TrustLevel.VERIFIED) continue;
            HeartbeatHealth health = context.heartbeat.health();
            if (!policy.enabled()) {
                context.heartbeatMissingPolls = 0;
                context.heartbeatTemporaryControl = false;
                continue;
            }
            if (health == HeartbeatHealth.MISSING) {
                if (context.heartbeatMissingPolls < Integer.MAX_VALUE) context.heartbeatMissingPolls++;
                if (!context.heartbeatTemporaryControl && context.heartbeatMissingPolls >= policy.consecutiveMissingPolls()) {
                    context.heartbeatTemporaryControl = true;
                    transitions.add(new HeartbeatMissingTransition(context.session.playerId(), context.session.id(),
                            HeartbeatMissingTransition.Kind.APPLY, policy.action(), context.heartbeatMissingPolls, clock.instant()));
                }
            } else {
                // STALE is never actionable and breaks a continuous MISSING run. Only a later
                // valid heartbeat returning ACTIVE reverses an already applied temporary control.
                context.heartbeatMissingPolls = 0;
                if (health == HeartbeatHealth.ACTIVE && context.heartbeatTemporaryControl) {
                    context.heartbeatTemporaryControl = false;
                    transitions.add(new HeartbeatMissingTransition(context.session.playerId(), context.session.id(),
                            HeartbeatMissingTransition.Kind.RECOVER, policy.action(), 0, clock.instant()));
                }
            }
        }
        return List.copyOf(transitions);
    }

    public synchronized void remove(UUID playerId) {
        SessionContext removed = sessions.remove(Objects.requireNonNull(playerId, "playerId"));
        if (removed != null) {
            evidenceRuntime.removeForSession(removed.session.id());
        }
        api.remove(playerId);
    }

    /** Issues a signed, short-lived, one-shot request without changing player risk or admission. */
    public synchronized Optional<EvidenceRequestRuntime.IssuedRequest> issueEvidenceRequest(
            UUID playerId, EvidenceRequestSpec spec, String operatorId) throws EnvelopeException {
        SessionContext context = sessions.get(Objects.requireNonNull(playerId, "playerId"));
        if (context == null || context.session.stage() != SessionStage.AUTHENTICATED) {
            return Optional.empty();
        }
        // expiresAt is the pre-authentication handshake deadline. An authenticated session is
        // live until disconnect/removal; evidence requests receive their own short TTL.
        Instant evidenceSessionExpiry = clock.instant().plus(ProtocolConstants.MAX_EVIDENCE_REQUEST_TTL);
        AuthenticatedObservationSession session = new AuthenticatedObservationSession(
                context.session.playerId(), context.session.id(),
                context.session.clientPublicKey().orElseThrow(), evidenceSessionExpiry);
        return evidenceRuntime.issue(session, spec, operatorId);
    }

    /** Receives EvidenceResponse/Begin/Chunk/Commit without entering the risk state machine. */
    public synchronized EvidenceIngressResult receiveEvidence(UUID playerId, byte[] encodedFrame) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(encodedFrame, "encodedFrame");
        SessionContext context = sessions.get(playerId);
        if (context == null || context.session.stage() != SessionStage.AUTHENTICATED
                || context.session.clientPublicKey().isEmpty()) {
            return new EvidenceIngressResult(
                    EvidenceIngressResult.Status.REJECTED, List.of(), "evidence session is not authenticated");
        }
        Instant evidenceSessionExpiry = clock.instant().plus(ProtocolConstants.MAX_EVIDENCE_REQUEST_TTL);
        AuthenticatedObservationSession session = new AuthenticatedObservationSession(
                context.session.playerId(), context.session.id(),
                context.session.clientPublicKey().orElseThrow(), evidenceSessionExpiry);
        return evidenceRuntime.receive(session, encodedFrame);
    }

    /** Cancels a pending evidence request without changing risk or admission. */
    public synchronized boolean cancelEvidenceRequest(UUID playerId) {
        return evidenceRuntime.cancelForPlayer(Objects.requireNonNull(playerId, "playerId"));
    }

    public PublicKey serverPublicKey() {
        return serverKeyPair.getPublic();
    }

    private HandshakeAction receiveClientHello(SessionContext context, SignedEnvelope envelope)
            throws EnvelopeException, InvalidProtocolBufferException {
        ClientHello hello = ClientHello.parseFrom(envelope.getPayload());
        PublicKey clientKey = Ed25519Keys.decodePublic(hello.getPublicKeyX509().toByteArray());
        envelopeCodec.verify(envelope, clientKey, replayGuard);
        if (context.session.stage() != SessionStage.CHALLENGE_SENT
                || !MessageDigest.isEqual(context.challenge, hello.getChallengeNonce().toByteArray())
                || hello.getLoader() == com.ellan.mcace.protocol.generated.LoaderType.LOADER_UNSPECIFIED
                || hello.getMinecraftVersion().isBlank()
                || hello.getBuildId().isBlank()) {
            return violation(context.session.playerId(), context, RiskEventType.PROTOCOL_VIOLATION);
        }
        if (!context.policy.getAllowedMinecraftVersionsList().contains(hello.getMinecraftVersion())
                || !context.policy.getAllowedLoadersList().contains(hello.getLoader())
                || (context.policy.getAllowedBuildIdsCount() > 0
                    && !context.policy.getAllowedBuildIdsList().contains(hello.getBuildId()))) {
            return violation(context.session.playerId(), context, RiskEventType.POLICY_MISMATCH);
        }
        context.session.identifyClient(clientKey);
        context.boundedPayloadReceiver = new BoundedPayloadTransferReceiver(context.session.id(), clock,
                ProtocolConstants.DEFAULT_BOUNDED_PAYLOAD_TTL);
        context.clientBuildId = hello.getBuildId();
        context.minecraftVersion = hello.getMinecraftVersion();
        context.loader = hello.getLoader();
        api.snapshot(context.session.playerId()).ifPresent(snapshot -> auditSession(context, snapshot));
        SignedEnvelope deferred = context.deferredAuthRequest;
        context.deferredAuthRequest = null;
        return deferred == null ? HandshakeAction.none() : receiveAuthRequest(context, deferred);
    }

    /**
     * Velocity may dispatch adjacent plugin-message events on different task workers. A valid
     * AUTH_REQUEST can therefore enter this synchronized coordinator just before the preceding
     * CLIENT_HELLO even though wire order was correct. Retain exactly one same-session envelope
     * until CLIENT_HELLO establishes the signing key; duplicates and every other out-of-order
     * packet remain protocol violations. The deferred envelope is still fully signature-, nonce-,
     * policy-, and session-verified before authentication can succeed.
     */
    private HandshakeAction receiveOrDeferAuthRequest(SessionContext context, SignedEnvelope envelope)
            throws EnvelopeException, InvalidProtocolBufferException {
        if (context.session.stage() == SessionStage.CHALLENGE_SENT) {
            if (context.deferredAuthRequest != null) {
                return violation(context.session.playerId(), context, RiskEventType.PROTOCOL_VIOLATION);
            }
            context.deferredAuthRequest = envelope;
            return HandshakeAction.none();
        }
        return receiveAuthRequest(context, envelope);
    }

    private HandshakeAction receiveAuthRequest(SessionContext context, SignedEnvelope envelope)
            throws EnvelopeException, InvalidProtocolBufferException {
        PublicKey clientKey = context.session.clientPublicKey()
                .orElseThrow(() -> new EnvelopeException("client key is not established"));
        envelopeCodec.verify(envelope, clientKey, replayGuard);
        return receiveAuthRequest(context, AuthRequest.parseFrom(envelope.getPayload()));
    }

    private HandshakeAction receiveBoundedPayload(
            SessionContext context, SignedEnvelope envelope, byte[] encodedFrame)
            throws EnvelopeException, InvalidProtocolBufferException, BoundedPayloadException {
        if (context.session.stage() == SessionStage.AUTHENTICATED) {
            return receiveArtifactObservationPayload(context, envelope, encodedFrame);
        }
        if (context.session.stage() != SessionStage.CLIENT_IDENTIFIED || context.boundedPayloadReceiver == null) {
            return violation(context.session.playerId(), context, RiskEventType.PROTOCOL_VIOLATION);
        }
        BoundedPayloadTransferLimits.validateFrameBytes(encodedFrame.length);
        PublicKey clientKey = context.session.clientPublicKey()
                .orElseThrow(() -> new EnvelopeException("client key is not established"));
        envelopeCodec.verify(envelope, clientKey, replayGuard);
        Optional<BoundedPayloadTransferReceiver.CompletedPayload> completed = context.boundedPayloadReceiver
                .acceptVerified(envelope);
        if (completed.isEmpty()) return HandshakeAction.none();
        BoundedPayloadTransferReceiver.CompletedPayload payload = completed.orElseThrow();
        if (payload.kind() != com.ellan.mcace.protocol.generated.BoundedPayloadKind.BOUNDED_PAYLOAD_AUTH_REQUEST) {
            return violation(context.session.playerId(), context, RiskEventType.PROTOCOL_VIOLATION);
        }
        return receiveAuthRequest(context, AuthRequest.parseFrom(payload.content()));
    }

    /**
     * Receives an optional complete post-auth snapshot. Any invalid input is ignored rather than
     * becoming a protocol violation: the authentication result and verified admission are fixed.
     */
    private HandshakeAction receiveArtifactObservationPayload(
            SessionContext context, SignedEnvelope envelope, byte[] encodedFrame)
            throws EnvelopeException, BoundedPayloadException {
        if (context.artifactObservationReceiver == null) {
            context.artifactObservationReceiver = new BoundedPayloadTransferReceiver(
                    context.session.id(), clock, ProtocolConstants.DEFAULT_BOUNDED_PAYLOAD_TTL);
        }
        BoundedPayloadTransferLimits.validateFrameBytes(encodedFrame.length);
        PublicKey clientKey = context.session.clientPublicKey()
                .orElseThrow(() -> new EnvelopeException("client key is not established"));
        envelopeCodec.verify(envelope, clientKey, replayGuard);
        Optional<BoundedPayloadTransferReceiver.CompletedPayload> completed = context.artifactObservationReceiver
                .acceptVerified(envelope);
        if (completed.isEmpty()) return HandshakeAction.none();
        BoundedPayloadTransferReceiver.CompletedPayload payload = completed.orElseThrow();
        if (payload.kind() != BoundedPayloadKind.BOUNDED_PAYLOAD_ARTIFACT_OBSERVATION) {
            return HandshakeAction.none();
        }
        try {
            acceptArtifactObservationUpdate(context, ArtifactObservationUpdate.parseFrom(payload.content()));
        } catch (InvalidProtocolBufferException | IllegalArgumentException ignored) {
            // Optional, client-reported telemetry must never penalize a verified session.
        }
        return HandshakeAction.none();
    }

    private void acceptArtifactObservationUpdate(SessionContext context, ArtifactObservationUpdate update) {
        if (update.getUpdateSequence() == 0L
                || Long.compareUnsigned(update.getUpdateSequence(), context.lastArtifactObservationSequence) <= 0
                || update.getObservedAtEpochMs() <= 0L
                || ageExceeds(clock.millis(), update.getObservedAtEpochMs(), ProtocolConstants.MAX_ARTIFACT_OBSERVATION_AGE)
                || update.getBaseManifestRootSha256().size() != 32
                || update.getPreviousAggregateRootSha256().size() != 32
                || update.getAggregateRootSha256().size() != 32
                || !MessageDigest.isEqual(update.getBaseManifestRootSha256().toByteArray(), context.authenticatedManifestRoot)
                || !MessageDigest.isEqual(update.getPreviousAggregateRootSha256().toByteArray(), context.lastArtifactObservationRoot)
                || update.getPolicySequence() != context.policy.getSequence()
                || !MessageDigest.isEqual(update.getPolicySha256().toByteArray(), context.policyDigest)
                || !validSelectedPackIds(update.getSelectedResourcePacksList(), "resource")
                || !validSelectedPackIds(update.getSelectedShaderPacksList(), "shader")
                || update.getModsCount() > ProtocolConstants.MAX_ARTIFACT_OBSERVATION_COUNT
                || update.getScopeManifestsList().stream().mapToInt(IntegrityScopeManifest::getEntriesCount).sum()
                        > ProtocolConstants.MAX_ARTIFACT_OBSERVATION_COUNT) {
            throw new IllegalArgumentException("artifact observation binding or budget is invalid");
        }
        AuthRequest candidate = context.authenticatedRequest.toBuilder()
                .clearMods().addAllMods(update.getModsList())
                .clearScopeManifests().addAllScopeManifests(update.getScopeManifestsList())
                .clearSelectedResourcePacks().addAllSelectedResourcePacks(update.getSelectedResourcePacksList())
                .clearSelectedShaderPacks().addAllSelectedShaderPacks(update.getSelectedShaderPacksList())
                .build();
        if (!validScopes(candidate, context.policy)) {
            throw new IllegalArgumentException("artifact observation scopes are invalid");
        }
        try {
            if (!MessageDigest.isEqual(aggregateRoot(candidate), update.getAggregateRootSha256().toByteArray())) {
                throw new IllegalArgumentException("artifact observation aggregate root does not match its complete snapshot");
            }
        } catch (EnvelopeException exception) {
            throw new IllegalArgumentException("artifact observation aggregate root cannot be derived", exception);
        }
        context.lastArtifactObservationSequence = update.getUpdateSequence();
        context.lastArtifactObservationRoot = update.getAggregateRootSha256().toByteArray();
        notifyArtifactObservationUpdate(new AuthenticatedManifest(
                context.session.playerId(), context.session.id(), context.policy, candidate,
                Instant.ofEpochMilli(update.getObservedAtEpochMs())));
    }

    private static boolean ageExceeds(long now, long observedAt, Duration maximumAge) {
        if (observedAt > now || now < 0L || observedAt < 0L) return true;
        long age = now - observedAt;
        return age < 0L || age > maximumAge.toMillis();
    }

    private HandshakeAction receiveAuthRequest(SessionContext context, AuthRequest request) throws EnvelopeException {
        if (context.session.stage() != SessionStage.CLIENT_IDENTIFIED) {
            return violation(context.session.playerId(), context, RiskEventType.PROTOCOL_VIOLATION);
        }
        if (!request.getPlayerUuid().equals(context.session.playerId().toString())
                || request.getManifestRootSha256().size() != 32
                || request.getEnvironmentSha256().size() != 32
                || request.getModsCount() > 4096
                || !validSelectedPackIds(request.getSelectedResourcePacksList(), "resource")
                || !validSelectedPackIds(request.getSelectedShaderPacksList(), "shader")
                || request.getPolicySequence() != context.policy.getSequence()
                || !MessageDigest.isEqual(context.policyDigest, request.getPolicySha256().toByteArray())) {
            return violation(context.session.playerId(), context, RiskEventType.POLICY_MISMATCH);
        }
        if (!validScopes(request, context.policy)) {
            return violation(context.session.playerId(), context, RiskEventType.PROTOCOL_VIOLATION);
        }
        context.session.authenticate(TrustLevel.VERIFIED);
        context.authenticatedAt = clock.instant();
        context.terminal = true;
        context.authenticatedRequest = request;
        context.authenticatedManifestRoot = request.getManifestRootSha256().toByteArray();
        context.lastArtifactObservationRoot = aggregateRoot(request);
        context.lastArtifactObservationSequence = 0L;
        context.heartbeat = new HeartbeatSessionStateMachine(
                context.session.id(),
                request.getManifestRootSha256().toByteArray(),
                request.getPolicySequence(),
                request.getPolicySha256().toByteArray(),
                aggregateRoot(request),
                clock);
        // The protocol owns the first-heartbeat grace period. Do not manufacture an immediate
        // MISSING transition at authentication time.
        context.lastHeartbeatHealth = context.heartbeat.health();
        PlayerSecuritySnapshot snapshot = publish(
                context.session.playerId(), TrustLevel.VERIFIED, AdmissionStatus.VERIFIED, List.of());
        auditSession(context, snapshot);
        notifyAuthenticatedManifest(new AuthenticatedManifest(
                context.session.playerId(), context.session.id(), context.policy, request, context.authenticatedAt));
        AuthResult result = AuthResult.newBuilder()
                .setAccepted(true)
                .setTrustLevel(TrustLevel.VERIFIED)
                .setRiskScore(snapshot.riskScore())
                // AuthResult expiry is admission-result freshness, not a heartbeat lease.
                // Heartbeats remain session-bound and independently signed after this TTL.
                .setExpiresAtEpochMs(clock.instant().plus(ProtocolConstants.AUTH_RESULT_TTL).toEpochMilli())
                .build();
        byte[] response = envelopeCodec.sign(
                PacketType.AUTH_RESULT,
                context.session.id(),
                result.toByteArray(),
                serverKeyPair.getPrivate()).toByteArray();
        return new HandshakeAction(List.of(response), Optional.of(snapshot), false);
    }

    /** Verifies a session-bound heartbeat without changing its successful admission snapshot. */
    private HandshakeAction receiveHeartbeat(SessionContext context, byte[] encodedFrame) {
        if (context.session.stage() != SessionStage.AUTHENTICATED || context.heartbeat == null) {
            return heartbeatViolation(context, "heartbeat before verified authentication");
        }
        try {
            PublicKey clientKey = context.session.clientPublicKey()
                    .orElseThrow(() -> new EnvelopeException("client key is not established"));
            context.heartbeat.accept(encodedFrame, envelopeCodec, clientKey, replayGuard);
            return HandshakeAction.none();
        } catch (HeartbeatException | EnvelopeException exception) {
            return heartbeatViolation(context, "rejected heartbeat");
        }
    }

    /** Heartbeat failures are audit-visible to adapters but never downgrade the verified session. */
    private HandshakeAction heartbeatViolation(SessionContext context, String ignoredReason) {
        return new HandshakeAction(List.of(), Optional.empty(), true);
    }

    /** A listener failure must never change a verified session's admission or routing result. */
    private void notifyAuthenticatedManifest(AuthenticatedManifest manifest) {
        try {
            authenticatedManifestHandler.accept(manifest);
        } catch (RuntimeException ignored) {
            // Manifest observations are audit-only; the handshake is already authenticated.
        }
    }

    /** Isolated audit path for post-auth snapshots; handler failures are deliberately inert. */
    private void notifyArtifactObservationUpdate(AuthenticatedManifest manifest) {
        try {
            artifactObservationUpdateHandler.accept(manifest);
        } catch (RuntimeException ignored) {
            // Post-auth integrity telemetry is advisory and must not affect session state.
        }
    }

    private HandshakeAction timeout(SessionContext context) {
        context.session.expire();
        context.terminal = true;
        List<ObservedRiskEvent> events = List.of(new ObservedRiskEvent(
                RiskEventType.MISSING_MCACE, "velocity-timeout", clock.instant(), true));
        PlayerSecuritySnapshot snapshot = publish(
                context.session.playerId(),
                TrustLevel.UNKNOWN,
                AdmissionStatus.LIMITED,
                events);
        auditSession(context, snapshot);
        auditRiskEvents(context, context.session.playerId(), events, ObservationOrigin.MISSING);
        return new HandshakeAction(List.of(), Optional.of(snapshot), false);
    }

    private HandshakeAction violation(UUID playerId, SessionContext context, RiskEventType type) {
        if (context != null) {
            context.session.reject();
            context.terminal = true;
        }
        List<ObservedRiskEvent> events = List.of(new ObservedRiskEvent(
                type, "protocol", clock.instant(), true));
        PlayerSecuritySnapshot snapshot = publish(
                playerId,
                TrustLevel.UNKNOWN,
                AdmissionStatus.LIMITED,
                events);
        if (context != null) {
            auditSession(context, snapshot);
        }
        auditRiskEvents(context, playerId, events, ObservationOrigin.SERVER_CONFIRMED);
        return new HandshakeAction(List.of(), Optional.of(snapshot), true);
    }

    private PlayerSecuritySnapshot publish(
            UUID playerId,
            TrustLevel trustLevel,
            AdmissionStatus admission,
            List<ObservedRiskEvent> events) {
        RiskAssessment assessment = riskEngine.evaluate(events);
        PlayerSecuritySnapshot snapshot = new PlayerSecuritySnapshot(
                playerId,
                trustLevel,
                admission,
                assessment.score(),
                assessment.band(),
                assessment.policyVersion(),
                clock.instant(),
                assessment.reasons());
        api.publish(snapshot);
        return snapshot;
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    private void auditSession(SessionContext context, PlayerSecuritySnapshot snapshot) {
        try {
            auditSink.upsertSession(new SessionAuditRecord(
                    context.session.id(),
                    context.session.playerId(),
                    context.policy.getServerId(),
                    context.policy.getPolicyVersion(),
                    context.policy.getSequence(),
                    context.session.stage(),
                    snapshot.trustLevel(),
                    snapshot.admissionStatus(),
                    snapshot.riskScore(),
                    snapshot.riskBand(),
                    context.clientBuildId,
                    context.minecraftVersion,
                    context.loader,
                    context.session.createdAt(),
                    snapshot.evaluatedAt(),
                    context.expiresAt));
        } catch (SecurityPersistenceException | RuntimeException exception) {
            reportPersistenceFailure(exception);
        }
    }

    private void auditRiskEvents(
            SessionContext context,
            UUID playerId,
            List<ObservedRiskEvent> events,
            ObservationOrigin origin) {
        for (ObservedRiskEvent event : events) {
            try {
                int weight = riskEngine.evaluate(List.of(event)).score();
                auditSink.appendRiskEvent(new RiskEventAuditRecord(
                        UUID.randomUUID(),
                        context == null ? "" : context.session.id(),
                        playerId,
                        event.type(),
                        weight,
                        event.source(),
                        origin,
                        event.corroborated(),
                        event.observedAt(),
                        "{}"));
            } catch (SecurityPersistenceException | RuntimeException exception) {
                reportPersistenceFailure(exception);
            }
        }
    }

    private void reportPersistenceFailure(Exception exception) {
        try {
            persistenceFailureHandler.accept(exception);
        } catch (RuntimeException ignored) {
            // Audit infrastructure and its reporter must never change player admission.
        }
    }

    private static boolean validScopes(AuthRequest request, SecurityPolicy policy) {
        if (request.getScopeManifestsCount() != policy.getIntegrityScopesCount()) {
            return false;
        }
        Map<String, IntegrityScopeRule> rules = new HashMap<>();
        for (IntegrityScopeRule rule : policy.getIntegrityScopesList()) {
            rules.put(rule.getScope(), rule);
        }
        Set<String> seenScopes = new HashSet<>();
        for (IntegrityScopeManifest manifest : request.getScopeManifestsList()) {
            IntegrityScopeRule rule = rules.get(manifest.getScope());
            if (rule == null || !seenScopes.add(manifest.getScope())
                    || !manifest.getRelativeRoot().equals(rule.getRelativeRoot())
                    || manifest.getRootSha256().size() != 32
                    || manifest.getEntryCount() != manifest.getEntriesCount()
                    || manifest.getEntriesCount() > rule.getMaxEntries()
                    || (!manifest.getPresent() && manifest.getEntriesCount() != 0)
                    || (rule.getRequired() && !manifest.getPresent())) {
                return false;
            }
            Set<String> paths = new HashSet<>();
            for (FileEntry entry : manifest.getEntriesList()) {
                if (!paths.add(entry.getRelativePath())
                        || !safeRelativePath(entry.getRelativePath())
                        || entry.getSha256().size() != 32
                        || entry.getFileSize() < 0
                        || entry.getFileSize() > rule.getMaxFileBytes()
                        || rule.getAllowedExtensionsList().stream()
                                .noneMatch(entry.getRelativePath().toLowerCase(java.util.Locale.ROOT)::endsWith)) {
                    return false;
                }
                if (rule.getExplicitRelativeFilesCount() > 0
                        && !rule.getExplicitRelativeFilesList().contains(entry.getRelativePath())) {
                    return false;
                }
            }
            try {
                if (!MessageDigest.isEqual(
                        manifest.getRootSha256().toByteArray(),
                        IntegrityDigests.scopeRoot(manifest.getEntriesList()))) {
                    return false;
                }
            } catch (IllegalArgumentException exception) {
                return false;
            }
        }
        return seenScopes.equals(rules.keySet());
    }

    private static boolean validSelectedPackIds(List<String> ids, String kind) {
        if (ids.size() > ProtocolConstants.MAX_SELECTED_PACKS) return false;
        Set<String> seen = new HashSet<>();
        for (String id : ids) {
            if (id == null || id.isBlank() || id.length() > ProtocolConstants.MAX_SELECTED_PACK_ID_CHARS
                    || id.chars().anyMatch(Character::isISOControl) || !seen.add(id)) {
                return false;
            }
        }
        return true;
    }

    /** Mirrors the documented client bundle digest so the accepted scope set binds each heartbeat. */
    private static byte[] aggregateRoot(AuthRequest request) throws EnvelopeException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update("mcace-integrity-bundle-v1\0".getBytes(StandardCharsets.US_ASCII));
            List<IntegrityScopeManifest> manifests = request.getScopeManifestsList().stream()
                    .sorted(java.util.Comparator.comparing(IntegrityScopeManifest::getScope))
                    .toList();
            for (IntegrityScopeManifest manifest : manifests) {
                byte[] name = manifest.getScope().getBytes(StandardCharsets.UTF_8);
                digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(name.length).array());
                digest.update(name);
                digest.update((byte) (manifest.getPresent() ? 1 : 0));
                digest.update(manifest.getRootSha256().toByteArray());
            }
            return digest.digest();
        } catch (NoSuchAlgorithmException exception) {
            throw new EnvelopeException("SHA-256 is unavailable", exception);
        }
    }

    private static boolean safeRelativePath(String path) {
        return !path.isBlank()
                && !path.startsWith("/")
                && !path.contains("\\")
                && !path.contains(":")
                && !path.equals("..")
                && !path.startsWith("../")
                && !path.endsWith("/..")
                && !path.contains("/../");
    }

    private static final class SessionContext {
        private final TrustSession session;
        private final byte[] challenge;
        private final Instant expiresAt;
        private final SecurityPolicy policy;
        private final byte[] policyDigest;
        private String clientBuildId = "";
        private String minecraftVersion = "";
        private com.ellan.mcace.protocol.generated.LoaderType loader =
                com.ellan.mcace.protocol.generated.LoaderType.LOADER_UNSPECIFIED;
        private boolean terminal;
        private BoundedPayloadTransferReceiver boundedPayloadReceiver;
        private SignedEnvelope deferredAuthRequest;
        private BoundedPayloadTransferReceiver artifactObservationReceiver;
        private HeartbeatSessionStateMachine heartbeat;
        private HeartbeatHealth lastHeartbeatHealth = HeartbeatHealth.MISSING;
        private int heartbeatMissingPolls;
        private boolean heartbeatTemporaryControl;
        private AuthRequest authenticatedRequest;
        private Instant authenticatedAt;
        private byte[] authenticatedManifestRoot;
        private byte[] lastArtifactObservationRoot;
        private long lastArtifactObservationSequence;

        private SessionContext(
                TrustSession session,
                byte[] challenge,
                Instant expiresAt,
                SecurityPolicy policy,
                byte[] policyDigest) {
            this.session = session;
            this.challenge = challenge.clone();
            this.expiresAt = expiresAt;
            this.policy = policy;
            this.policyDigest = policyDigest.clone();
        }
    }
}
