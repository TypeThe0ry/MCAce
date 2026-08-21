package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.session.HandshakeAction;
import com.ellan.mcace.core.session.HeartbeatTransition;
import com.ellan.mcace.core.session.HeartbeatMissingPolicy;
import com.ellan.mcace.core.session.HeartbeatMissingTransition;
import com.ellan.mcace.core.session.ServerHandshakeCoordinator;
import com.ellan.mcace.core.evidence.EvidenceIngressResult;
import com.ellan.mcace.core.evidence.EvidenceAdminService;
import com.ellan.mcace.core.evidence.EvidenceContentStore;
import com.ellan.mcace.core.evidence.EvidencePacketClassifier;
import com.ellan.mcace.core.evidence.EvidenceRequestRuntime;
import com.ellan.mcace.core.evidence.EvidenceRequestSpec;
import com.ellan.mcace.core.evidence.LoopbackEvidenceReviewService;
import com.ellan.mcace.core.proxy.SharedProxyDispositionPolicyRuntime;
import com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent;
import com.ellan.mcace.core.proxy.ShadowBackendContextRuntime;
import com.ellan.mcace.core.federation.FederationRuntime;
import com.ellan.mcace.core.federation.FederationSubject;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.policy.PolicyException;
import com.ellan.mcace.sdk.MCAceApi;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.security.PrivateKey;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/** Reuses {@link ServerHandshakeCoordinator}; this class contains no risk or punishment logic. */
public final class CoordinatorBungeeSessionBridge implements BungeeSessionBridge {
    private final ServerHandshakeCoordinator coordinator;
    private final MCAceApi api;
    private final PrivateKey admissionSigningKey;
    private final SharedProxyDispositionPolicyRuntime dispositionPolicyRuntime;
    private final BungeeDispositionPolicyPublisher dispositionPolicyPublisher;
    private final AutoCloseable manifestAuditQueue;
    private final EvidenceContentStore evidenceContentStore;
    private final EvidenceAdminService evidenceAdmin;
    private volatile LoopbackEvidenceReviewService evidenceReviewService;
    private final BungeeDispositionExecutionMode dispositionExecutionMode;
    private final String dispositionLimitedServer;
    private final String dispositionQuarantineServer;
    private final HeartbeatMissingPolicy heartbeatMissingPolicy;
    private final FederationRuntime federationRuntime;
    private final AutoCloseable federationLifecycle;
    private final AtomicReference<Consumer<AuthenticatedManifestDispositionEvent>> dispositionEventHandler =
            new AtomicReference<>(ignored -> { });
    private volatile ShadowBackendContextRuntime shadowBackendContextRuntime;

    public CoordinatorBungeeSessionBridge(ServerHandshakeCoordinator coordinator, MCAceApi api) {
        this(coordinator, api, null);
    }

    public CoordinatorBungeeSessionBridge(
            ServerHandshakeCoordinator coordinator, MCAceApi api, PrivateKey admissionSigningKey) {
        this(coordinator, api, admissionSigningKey, null);
    }

    public CoordinatorBungeeSessionBridge(
            ServerHandshakeCoordinator coordinator,
            MCAceApi api,
            PrivateKey admissionSigningKey,
            SharedProxyDispositionPolicyRuntime dispositionPolicyRuntime) {
        this(coordinator, api, admissionSigningKey, dispositionPolicyRuntime, null);
    }

    public CoordinatorBungeeSessionBridge(
            ServerHandshakeCoordinator coordinator,
            MCAceApi api,
            PrivateKey admissionSigningKey,
            SharedProxyDispositionPolicyRuntime dispositionPolicyRuntime,
            BungeeDispositionPolicyPublisher dispositionPolicyPublisher) {
        this(coordinator, api, admissionSigningKey, dispositionPolicyRuntime, dispositionPolicyPublisher, null);
    }

    public CoordinatorBungeeSessionBridge(ServerHandshakeCoordinator coordinator, MCAceApi api, PrivateKey admissionSigningKey,
            SharedProxyDispositionPolicyRuntime dispositionPolicyRuntime, BungeeDispositionPolicyPublisher dispositionPolicyPublisher,
            AutoCloseable manifestAuditQueue) {
        this(coordinator, api, admissionSigningKey, dispositionPolicyRuntime, dispositionPolicyPublisher,
                manifestAuditQueue, EvidenceContentStore.discard(), null);
    }

    public CoordinatorBungeeSessionBridge(ServerHandshakeCoordinator coordinator, MCAceApi api, PrivateKey admissionSigningKey,
            SharedProxyDispositionPolicyRuntime dispositionPolicyRuntime, BungeeDispositionPolicyPublisher dispositionPolicyPublisher,
            AutoCloseable manifestAuditQueue, EvidenceContentStore evidenceContentStore,
            EvidenceAdminService evidenceAdmin) {
        this(coordinator, api, admissionSigningKey, dispositionPolicyRuntime, dispositionPolicyPublisher,
                manifestAuditQueue, evidenceContentStore, evidenceAdmin,
                BungeeDispositionExecutionMode.MONITOR, "restricted", "",
                HeartbeatMissingPolicy.disabled(), null, null);
    }

    public CoordinatorBungeeSessionBridge(ServerHandshakeCoordinator coordinator, MCAceApi api, PrivateKey admissionSigningKey,
            SharedProxyDispositionPolicyRuntime dispositionPolicyRuntime, BungeeDispositionPolicyPublisher dispositionPolicyPublisher,
            AutoCloseable manifestAuditQueue, EvidenceContentStore evidenceContentStore,
            EvidenceAdminService evidenceAdmin, BungeeDispositionExecutionMode dispositionExecutionMode,
            String dispositionRestrictedServer) {
        this(coordinator, api, admissionSigningKey, dispositionPolicyRuntime, dispositionPolicyPublisher,
                manifestAuditQueue, evidenceContentStore, evidenceAdmin, dispositionExecutionMode,
                dispositionRestrictedServer, "", HeartbeatMissingPolicy.disabled(), null, null);
    }

    public CoordinatorBungeeSessionBridge(ServerHandshakeCoordinator coordinator, MCAceApi api, PrivateKey admissionSigningKey,
            SharedProxyDispositionPolicyRuntime dispositionPolicyRuntime, BungeeDispositionPolicyPublisher dispositionPolicyPublisher,
            AutoCloseable manifestAuditQueue, EvidenceContentStore evidenceContentStore,
            EvidenceAdminService evidenceAdmin, BungeeDispositionExecutionMode dispositionExecutionMode,
            String dispositionRestrictedServer, HeartbeatMissingPolicy heartbeatMissingPolicy) {
        this(coordinator, api, admissionSigningKey, dispositionPolicyRuntime, dispositionPolicyPublisher,
                manifestAuditQueue, evidenceContentStore, evidenceAdmin, dispositionExecutionMode,
                dispositionRestrictedServer, "", heartbeatMissingPolicy, null, null);
    }

    public CoordinatorBungeeSessionBridge(ServerHandshakeCoordinator coordinator, MCAceApi api,
            PrivateKey admissionSigningKey, SharedProxyDispositionPolicyRuntime dispositionPolicyRuntime,
            BungeeDispositionPolicyPublisher dispositionPolicyPublisher, AutoCloseable manifestAuditQueue,
            EvidenceContentStore evidenceContentStore, EvidenceAdminService evidenceAdmin,
            BungeeDispositionExecutionMode dispositionExecutionMode, String dispositionRestrictedServer,
            HeartbeatMissingPolicy heartbeatMissingPolicy, FederationRuntime federationRuntime) {
        this(coordinator, api, admissionSigningKey, dispositionPolicyRuntime, dispositionPolicyPublisher,
                manifestAuditQueue, evidenceContentStore, evidenceAdmin, dispositionExecutionMode,
                dispositionRestrictedServer, "", heartbeatMissingPolicy, federationRuntime, null);
    }

    public CoordinatorBungeeSessionBridge(ServerHandshakeCoordinator coordinator, MCAceApi api,
            PrivateKey admissionSigningKey, SharedProxyDispositionPolicyRuntime dispositionPolicyRuntime,
            BungeeDispositionPolicyPublisher dispositionPolicyPublisher, AutoCloseable manifestAuditQueue,
            EvidenceContentStore evidenceContentStore, EvidenceAdminService evidenceAdmin,
            BungeeDispositionExecutionMode dispositionExecutionMode, String dispositionLimitedServer,
            String dispositionQuarantineServer, HeartbeatMissingPolicy heartbeatMissingPolicy,
            FederationRuntime federationRuntime, AutoCloseable federationLifecycle) {
        this.coordinator = Objects.requireNonNull(coordinator, "coordinator");
        this.api = Objects.requireNonNull(api, "api");
        this.admissionSigningKey = admissionSigningKey;
        this.dispositionPolicyRuntime = dispositionPolicyRuntime;
        this.dispositionPolicyPublisher = dispositionPolicyPublisher;
        this.manifestAuditQueue = manifestAuditQueue;
        this.evidenceContentStore = Objects.requireNonNull(evidenceContentStore, "evidenceContentStore");
        this.evidenceAdmin = evidenceAdmin;
        this.dispositionExecutionMode = Objects.requireNonNull(dispositionExecutionMode, "dispositionExecutionMode");
        this.dispositionLimitedServer = Objects.requireNonNull(dispositionLimitedServer, "dispositionLimitedServer");
        this.dispositionQuarantineServer = Objects.requireNonNull(dispositionQuarantineServer, "dispositionQuarantineServer");
        this.heartbeatMissingPolicy = Objects.requireNonNull(heartbeatMissingPolicy, "heartbeatMissingPolicy");
        this.federationRuntime = federationRuntime;
        this.federationLifecycle = federationLifecycle;
    }

    public CoordinatorBungeeSessionBridge(ServerHandshakeCoordinator coordinator, MCAceApi api,
            PrivateKey admissionSigningKey, SharedProxyDispositionPolicyRuntime dispositionPolicyRuntime,
            BungeeDispositionPolicyPublisher dispositionPolicyPublisher, AutoCloseable manifestAuditQueue,
            EvidenceContentStore evidenceContentStore, EvidenceAdminService evidenceAdmin,
            BungeeDispositionExecutionMode dispositionExecutionMode, String dispositionRestrictedServer,
            HeartbeatMissingPolicy heartbeatMissingPolicy, FederationRuntime federationRuntime,
            AutoCloseable federationLifecycle) {
        this(coordinator, api, admissionSigningKey, dispositionPolicyRuntime, dispositionPolicyPublisher,
                manifestAuditQueue, evidenceContentStore, evidenceAdmin, dispositionExecutionMode,
                dispositionRestrictedServer, "", heartbeatMissingPolicy, federationRuntime, federationLifecycle);
    }

    @Override
    public Optional<byte[]> begin(UUID playerId) {
        try {
            return Optional.of(coordinator.begin(Objects.requireNonNull(playerId, "playerId")));
        } catch (EnvelopeException | PolicyException exception) {
            return Optional.empty();
        }
    }

    @Override
    public BungeeBridgeAction receive(UUID playerId, byte[] encodedFrame) {
        if (EvidencePacketClassifier.isServerOnlyEvidenceFrame(encodedFrame)) {
            return BungeeBridgeAction.none();
        }
        if (EvidencePacketClassifier.isEvidenceFrame(encodedFrame)) {
            EvidenceIngressResult result = coordinator.receiveEvidence(
                    Objects.requireNonNull(playerId, "playerId"), encodedFrame.clone());
            return new BungeeBridgeAction(result.outboundFrames(), Optional.empty(), false);
        }
        HandshakeAction action = coordinator.receive(
                Objects.requireNonNull(playerId, "playerId"),
                Objects.requireNonNull(encodedFrame, "encodedFrame").clone());
        return new BungeeBridgeAction(action.outboundFrames(), action.snapshot(), action.protocolViolation());
    }

    @Override
    public Optional<EvidenceRequestRuntime.IssuedRequest> issueEvidenceRequest(
            UUID playerId, EvidenceRequestSpec spec, String operatorId) throws EnvelopeException {
        return coordinator.issueEvidenceRequest(playerId, spec, operatorId);
    }

    @Override
    public boolean cancelEvidenceRequest(UUID playerId) {
        return coordinator.cancelEvidenceRequest(Objects.requireNonNull(playerId, "playerId"));
    }

    @Override
    public EvidenceRequestSpec evidenceRequestSpec(com.ellan.mcace.protocol.generated.EvidenceCaptureScope scope,
                                                   String caseId) {
        EvidenceContentStore.RetentionDisclosure disclosure = evidenceContentStore.retentionDisclosure();
        return disclosure.rawContentRetained()
                ? EvidenceRequestSpec.retainedScreenshot(scope, caseId,
                        com.ellan.mcace.protocol.ProtocolConstants.MAX_EVIDENCE_REQUEST_TTL,
                        disclosure.retentionSeconds(), disclosure.retentionPolicyId(), disclosure.retentionPurpose())
                : EvidenceRequestSpec.screenshot(scope, caseId);
    }

    @Override public Optional<EvidenceAdminService> evidenceAdmin() { return Optional.ofNullable(evidenceAdmin); }

    @Override public Optional<LoopbackEvidenceReviewService> evidenceReviewService() {
        return Optional.ofNullable(evidenceReviewService);
    }

    void setEvidenceReviewService(LoopbackEvidenceReviewService service) {
        LoopbackEvidenceReviewService prior = evidenceReviewService;
        evidenceReviewService = service;
        if (prior != null && prior != service) {
            prior.close();
        }
    }

    @Override
    public EvidenceIngressResult receiveEvidence(UUID playerId, byte[] encodedFrame) {
        return coordinator.receiveEvidence(playerId, encodedFrame);
    }

    @Override
    public List<PlayerSecuritySnapshot> expireTimedOut() {
        return coordinator.expireTimedOut();
    }

    @Override
    public List<HeartbeatTransition> pollHeartbeatTransitions() {
        return coordinator.pollHeartbeatTransitions();
    }

    @Override public List<HeartbeatMissingTransition> pollHeartbeatMissingTransitions() {
        return coordinator.pollHeartbeatMissingTransitions(heartbeatMissingPolicy);
    }
    @Override public HeartbeatMissingPolicy heartbeatMissingPolicy() { return heartbeatMissingPolicy; }

    @Override
    public void remove(UUID playerId) {
        coordinator.remove(Objects.requireNonNull(playerId, "playerId"));
        ShadowBackendContextRuntime runtime = shadowBackendContextRuntime;
        if (runtime != null) runtime.clear(playerId);
    }

    @Override
    public MCAceApi api() {
        return api;
    }

    @Override public Optional<FederationRuntime> federationRuntime() {
        return Optional.ofNullable(federationRuntime);
    }

    @Override public Optional<FederationSubject> federationSubject(UUID playerId) {
        return coordinator.federationSubject(Objects.requireNonNull(playerId, "playerId"));
    }

    @Override
    public Optional<PrivateKey> admissionSigningKey() {
        return Optional.ofNullable(admissionSigningKey);
    }

    @Override
    public Optional<SharedProxyDispositionPolicyRuntime> dispositionPolicyRuntime() {
        return Optional.ofNullable(dispositionPolicyRuntime);
    }

    @Override
    public Optional<ShadowBackendContextRuntime> shadowBackendContextRuntime() {
        return Optional.ofNullable(shadowBackendContextRuntime);
    }

    void setShadowBackendContextRuntime(ShadowBackendContextRuntime runtime) {
        if (shadowBackendContextRuntime != null) {
            throw new IllegalStateException("shadow backend context runtime is already installed");
        }
        shadowBackendContextRuntime = Objects.requireNonNull(runtime, "runtime");
    }

    @Override
    public Optional<BungeeDispositionPolicyPublisher> dispositionPolicyPublisher() {
        return Optional.ofNullable(dispositionPolicyPublisher);
    }

    @Override
    public boolean isCurrentAuthenticatedSession(UUID playerId, String sessionId) {
        return coordinator.isCurrentAuthenticatedSession(
                Objects.requireNonNull(playerId, "playerId"), Objects.requireNonNull(sessionId, "sessionId"));
    }

    @Override
    public Optional<String> currentAuthenticatedSessionId(UUID playerId) {
        return coordinator.currentAuthenticatedSessionId(Objects.requireNonNull(playerId, "playerId"));
    }

    @Override
    public void setDispositionEventHandler(Consumer<AuthenticatedManifestDispositionEvent> handler) {
        dispositionEventHandler.set(Objects.requireNonNull(handler, "handler"));
    }

    void emitDispositionEvent(AuthenticatedManifestDispositionEvent event) {
        dispositionEventHandler.get().accept(Objects.requireNonNull(event, "event"));
    }

    @Override
    public BungeeDispositionExecutionMode dispositionExecutionMode() {
        return dispositionExecutionMode;
    }

    @Override
    public Optional<String> dispositionRestrictedServer() {
        return dispositionLimitedServer.isBlank() ? Optional.empty() : Optional.of(dispositionLimitedServer);
    }

    @Override
    public Optional<String> dispositionLimitedServer() {
        return dispositionRestrictedServer();
    }

    @Override
    public Optional<String> dispositionQuarantineServer() {
        return dispositionQuarantineServer.isBlank() ? Optional.empty() : Optional.of(dispositionQuarantineServer);
    }

    @Override public void close() {
        LoopbackEvidenceReviewService review = evidenceReviewService;
        evidenceReviewService = null;
        if (review != null) review.close();
        if (manifestAuditQueue != null) try { manifestAuditQueue.close(); } catch (Exception ignored) { }
        ShadowBackendContextRuntime contextRuntime = shadowBackendContextRuntime;
        shadowBackendContextRuntime = null;
        if (contextRuntime != null) contextRuntime.close();
        if (federationLifecycle != null) try { federationLifecycle.close(); } catch (Exception ignored) { }
    }
}
