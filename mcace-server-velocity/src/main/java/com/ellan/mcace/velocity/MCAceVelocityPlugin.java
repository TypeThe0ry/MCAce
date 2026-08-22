package com.ellan.mcace.velocity;

import com.ellan.mcace.core.admission.SignedAdmissionSnapshotCodec;
import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.core.persistence.AsyncSecurityAuditSink;
import com.ellan.mcace.core.persistence.SecurityAuditSink;
import com.ellan.mcace.core.persistence.SecurityPersistenceException;
import com.ellan.mcace.core.disposition.EvaluationContext;
import com.ellan.mcace.core.evidence.EvidenceIngressResult;
import com.ellan.mcace.core.evidence.EvidencePacketClassifier;
import com.ellan.mcace.core.evidence.EvidenceAdminService;
import com.ellan.mcace.core.evidence.EvidenceAuditSink;
import com.ellan.mcace.core.evidence.EvidenceContentStore;
import com.ellan.mcace.core.evidence.EvidenceRequestSpec;
import com.ellan.mcace.core.evidence.EvidenceReviewEndpointConfiguration;
import com.ellan.mcace.core.evidence.LoopbackEvidenceReviewService;
import com.ellan.mcace.core.evidence.EvidenceStorageConfiguration;
import com.ellan.mcace.core.evidence.EvidenceStorageRuntime;
import com.ellan.mcace.core.evidence.FileEvidenceAuditSink;
import com.ellan.mcace.core.federation.FederationGrantResult;
import com.ellan.mcace.core.federation.FederationIssueResult;
import com.ellan.mcace.core.federation.FederationPresentationResult;
import com.ellan.mcace.core.federation.FederationRuntime;
import com.ellan.mcace.core.federation.FederationRuntimeStatus;
import com.ellan.mcace.core.federation.FederationSubject;
import com.ellan.mcace.core.proxy.AuthenticatedManifestAuditResult;
import com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent;
import com.ellan.mcace.core.proxy.AuthenticatedManifestEvaluator;
import com.ellan.mcace.core.proxy.AuthenticatedManifestObservationDeriver;
import com.ellan.mcace.core.proxy.BoundedAuthenticatedManifestAuditQueue;
import com.ellan.mcace.core.proxy.ArtifactObservationAuditSink;
import com.ellan.mcace.core.proxy.ArtifactObservationAuditRecord;
import com.ellan.mcace.core.proxy.AdministratorDispositionReviewRequest;
import com.ellan.mcace.core.proxy.FileTrustedDispositionAuthorizationSink;
import com.ellan.mcace.core.proxy.TrustedDispositionAuthorizationRuntime;
import com.ellan.mcace.core.proxy.TrustedDispositionCommitments;
import com.ellan.mcace.core.proxy.FileArtifactObservationAuditSink;
import com.ellan.mcace.core.proxy.ProxyPolicyRefreshStatus;
import com.ellan.mcace.core.proxy.ShadowBackendContextRuntime;
import com.ellan.mcace.core.risk.RiskEngine;
import com.ellan.mcace.core.risk.RiskPolicy;
import com.ellan.mcace.core.session.HandshakeAction;
import com.ellan.mcace.core.session.HeartbeatTransition;
import com.ellan.mcace.core.session.HeartbeatMissingTransition;
import com.ellan.mcace.core.session.ServerHandshakeCoordinator;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.policy.PolicyException;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyVerification;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.storage.postgres.Ed25519EvidenceChainSigner;
import com.ellan.mcace.storage.postgres.PostgresDataSources;
import com.ellan.mcace.storage.postgres.PostgresSchemaMigrator;
import com.ellan.mcace.storage.postgres.PostgresSecurityAuditRepository;
import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.PluginMessageEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.player.PlayerChannelRegisterEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.event.player.ServerPostConnectEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.ServerConnection;
import net.kyori.adventure.text.Component;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;

@Plugin(
        id = "mcace",
        name = "MCAce",
        version = "0.1.0-SNAPSHOT",
        description = "MCAce trusted-client admission layer",
        authors = {"EllanServer"})
public final class MCAceVelocityPlugin {
    private static final Duration BACKEND_SNAPSHOT_TTL = Duration.ofSeconds(15);
    private static final Duration BACKEND_REFRESH_INTERVAL = Duration.ofSeconds(5);
    private static final Duration DISPOSITION_POLICY_REFRESH_INTERVAL = Duration.ofSeconds(30);

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;
    private final InMemoryMCAceApi api = new InMemoryMCAceApi();
    private final Object connectionLifecycleLock = new Object();
    private final VelocityLoginLifecycle loginLifecycle = new VelocityLoginLifecycle();
    /** Guarded by {@link #connectionLifecycleLock}. */
    private final Map<UUID, VelocityLoginLifecycle.LoginTicket> challengedPlayers = new HashMap<>();
    private final ConcurrentMap<UUID, Instant> lastBackendPublish = new ConcurrentHashMap<>();
    private ServerHandshakeCoordinator handshakes;
    private VelocityAdmissionConfig admissionConfig;
    private ServerPolicyManager policyManager;
    private AsyncSecurityAuditSink asyncAuditSink;
    private SignedAdmissionSnapshotCodec admissionSnapshotCodec;
    private PrivateKey admissionSigningKey;
    private AtomicLong admissionSequence;
    private Clock clock;
    private VelocityDispositionPolicyRuntime dispositionPolicies;
    private VelocityDispositionPolicyStatus lastDispositionPolicyStatus;
    private VelocityDispositionPolicyPublisher dispositionPublisher;
    private VelocityDispositionRoutes dispositionRoutes;
    private BoundedAuthenticatedManifestAuditQueue manifestAuditQueue;
    private BoundedAuthenticatedManifestAuditQueue artifactObservationAuditQueue;
    private AuthenticatedManifestEvaluator manifestEvaluator;
    private ShadowBackendContextRuntime backendContextRuntime;
    private VelocityDispositionExecutor dispositionExecutor;
    private VelocityDeferredDispositionRoutes deferredDispositionRoutes;
    private VelocityDeferredAdmissionRoutes deferredAdmissionRoutes;
    private final VelocityBackendReadyBarrier backendReadyBarrier = new VelocityBackendReadyBarrier();
    private EvidenceAdminService evidenceAdmin;
    private EvidenceContentStore evidenceContentStore;
    private EvidenceReviewEndpointConfiguration evidenceReviewConfiguration;
    private EvidenceAuditSink evidenceAuditSink;
    private LoopbackEvidenceReviewService evidenceReviewService;
    private ArtifactObservationAuditSink artifactObservationAudit;
    private TrustedDispositionAuthorizationRuntime trustedDispositionAuthorizations;
    private VelocityFederationLifecycle federationLifecycle;
    private FederationRuntime federationRuntime;

    @Inject
    public MCAceVelocityPlugin(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        try {
            admissionConfig = VelocityAdmissionConfig.loadOrCreate(dataDirectory.resolve("mcace.properties"));
            dispositionRoutes = VelocityDispositionRoutes.resolve(
                    admissionConfig, name -> server.getServer(name).isPresent());
            if (dispositionRoutes.validationStatus() != VelocityDispositionRoutes.ValidationStatus.ACTIVE
                    && admissionConfig.mode() == VelocityAdmissionConfig.Mode.LIMITED_ROUTE) {
                // Do not include configured target names, player data, or config contents in this
                // fixed status record.  A bad route configuration must not disable handshakes.
                logger.error("MCAce high-impact disposition routing disabled: status={}",
                        dispositionRoutes.validationStatus());
            }
            evidenceReviewConfiguration = loadEvidenceReviewConfiguration();
            KeyPair identity = ServerIdentityStore.loadOrCreate(dataDirectory.resolve("identity"));
            clock = Clock.systemUTC();
            federationLifecycle = VelocityFederationLifecycle.loadOrDisabled(
                    dataDirectory, clock, new SecureRandom(), identity,
                    admissionConfig.policy().serverId(),
                    exception -> logger.warn(
                            "MCAce federation disabled because its local configuration/audit is invalid", exception));
            federationRuntime = federationLifecycle.runtime();
            dispositionPolicies = VelocityDispositionPolicyRuntime.create(
                    dataDirectory.resolve("policy").resolve("signed-disposition-policy.pb"), clock, identity);
            lastDispositionPolicyStatus = dispositionPolicies.refresh();
            manifestEvaluator = new AuthenticatedManifestEvaluator(
                    new AuthenticatedManifestObservationDeriver(), dispositionPolicies.coreRuntime(), clock);
            backendContextRuntime = new ShadowBackendContextRuntime(
                    "velocity",
                    new AuthenticatedManifestObservationDeriver(),
                    dispositionPolicies.coreRuntime(),
                    clock,
                    record -> logger.info(
                            "MCAce backend context shadow audit: player={} backend={} world={} gameMode={} "
                                    + "observations={} actions={} issues={} status={} (no admission or disposition effect)",
                            record.playerId(), record.backendId(), record.worldId(), record.gameMode(),
                            record.observationCount(), record.actionCounts(), record.consistencyIssueCount(),
                            record.policyStatus()));
            manifestAuditQueue = new BoundedAuthenticatedManifestAuditQueue(
                    1, 32, this::auditAuthenticatedManifest);
            artifactObservationAuditQueue = new BoundedAuthenticatedManifestAuditQueue(
                    1, 32, this::auditArtifactObservationUpdate);
            artifactObservationAudit = new FileArtifactObservationAuditSink(
                    dataDirectory.resolve("artifact-observation-audit.log"), 8L * 1024 * 1024);
            try {
                trustedDispositionAuthorizations = new TrustedDispositionAuthorizationRuntime(
                        dispositionPolicies.coreRuntime(),
                        new FileTrustedDispositionAuthorizationSink(
                                dataDirectory.resolve("trusted-disposition-authorizations.log"),
                                8L * 1024 * 1024));
            } catch (IOException exception) {
                trustedDispositionAuthorizations = null;
                logger.warn("MCAce administrator-reviewed disposition is disabled because its durable audit is unavailable");
            }
            dispositionPublisher = VelocityDispositionPolicyPublisher.create(
                    dataDirectory, clock, identity, dispositionPolicies);
            try {
                dispositionPublisher.createSafeDefaultConfigurationIfMissing();
            } catch (IOException exception) {
                logger.error("Could not create MCAce disposition policy example; publishing remains disabled until fixed", exception);
            }
            policyManager = new ServerPolicyManager(
                    dataDirectory.resolve("policy").resolve("signed-policy.pb"),
                    clock,
                    identity,
                    admissionConfig.policy());
            PolicyVerification activePolicy = PolicyDocuments.verifyDetailed(
                    policyManager.current(), identity.getPublic(), clock, Duration.ofSeconds(30));
            SecurityAuditSink auditSink = configureAuditStorage(identity, clock);
            evidenceAuditSink = new FileEvidenceAuditSink(
                    dataDirectory.resolve("evidence-audit.log"), 8L * 1024 * 1024);
            EvidenceStorageRuntime evidenceStorage = EvidenceStorageConfiguration.loadOrCreate(
                    dataDirectory.resolve("evidence-storage.properties"), dataDirectory.resolve("evidence"))
                    .createRuntime(clock, new SecureRandom(), evidenceAuditSink);
            evidenceAdmin = evidenceStorage.adminService();
            evidenceContentStore = evidenceStorage.contentStore();
            startEvidenceReview(evidenceStorage);
            handshakes = new ServerHandshakeCoordinator(
                    clock,
                    new SecureRandom(),
                    identity,
                    new RiskEngine(RiskPolicy.defaults()),
                    api,
                    admissionConfig.handshakeTimeout(),
                    policyManager,
                    auditSink,
                    this::logPersistenceFailure,
                    this::enqueueManifestAudit,
                    this::enqueueArtifactObservationAudit,
                    evidenceContentStore,
                    evidenceAuditSink);
            dispositionExecutor = new VelocityDispositionExecutor(
                    dispositionRoutes.effectiveMode(), new VelocityDispositionExecutor.Actions() {
                        @Override
                        public boolean isCurrentAuthenticatedSession(UUID playerId, String sessionId) {
                            return coordinator().isCurrentAuthenticatedSession(playerId, sessionId);
                        }

                        @Override
                        public boolean isVerifiedAdmission(UUID playerId) {
                            return api.snapshot(playerId)
                                    .map(snapshot -> snapshot.verified()
                                            && snapshot.admissionStatus() == AdmissionStatus.VERIFIED)
                                    .orElse(false);
                        }

                        @Override
                        public boolean isCurrentAuthorizationContext(
                                AuthenticatedManifestDispositionEvent event) {
                            synchronized (connectionLifecycleLock) {
                                return currentAuthorizationContextMatchesLocked(event);
                            }
                        }

                        @Override
                        public boolean sendMessage(UUID playerId, String sessionId, String message) {
                            synchronized (connectionLifecycleLock) {
                                Optional<PhysicalLogin> login = currentAuthenticatedLoginLocked(playerId, sessionId);
                                if (login.isEmpty()) return false;
                                login.orElseThrow().player().sendMessage(Component.text(message));
                                return true;
                            }
                        }

                        @Override
                        public VelocityDispositionExecutor.RouteOutcome routeToLimited(UUID playerId, String sessionId) {
                            return routeDispositionOutcome(
                                    playerId, sessionId, com.ellan.mcace.core.disposition.DispositionAction.LIMIT);
                        }

                        @Override
                        public VelocityDispositionExecutor.RouteOutcome routeToLimited(
                                AuthenticatedManifestDispositionEvent event) {
                            synchronized (connectionLifecycleLock) {
                                return executeWithCurrentDispositionPolicy(event, () ->
                                        routeDispositionOutcome(
                                                event.playerId(), event.sessionId(),
                                                event.highestAction(), event.authorizationId()))
                                        .orElse(VelocityDispositionExecutor.RouteOutcome.UNAVAILABLE);
                            }
                        }

                        @Override
                        public VelocityDispositionExecutor.RouteOutcome routeToQuarantine(UUID playerId, String sessionId) {
                            return routeDispositionOutcome(
                                    playerId, sessionId, com.ellan.mcace.core.disposition.DispositionAction.QUARANTINE);
                        }

                        @Override
                        public VelocityDispositionExecutor.RouteOutcome routeToQuarantine(
                                AuthenticatedManifestDispositionEvent event) {
                            synchronized (connectionLifecycleLock) {
                                return executeWithCurrentDispositionPolicy(event, () ->
                                        routeDispositionOutcome(
                                                event.playerId(), event.sessionId(),
                                                event.highestAction(), event.authorizationId()))
                                        .orElse(VelocityDispositionExecutor.RouteOutcome.UNAVAILABLE);
                            }
                        }

                        @Override
                        public boolean deny(UUID playerId, String sessionId, String message) {
                            synchronized (connectionLifecycleLock) {
                                Optional<PhysicalLogin> login = currentAuthenticatedLoginLocked(playerId, sessionId);
                                if (login.isEmpty()) return false;
                                PhysicalLogin current = login.orElseThrow();
                                // Check, terminal mark, and disconnect share one login-lifecycle
                                // boundary, so a reconnect cannot inherit or receive this DENY.
                                deferredDispositionRoutes.markDenied(
                                        playerId, sessionId, current.ticket(), current.player());
                                deferredAdmissionRoutes.clear(playerId);
                                current.player().disconnect(Component.text(message));
                                return true;
                            }
                        }

                        @Override
                        public boolean deny(AuthenticatedManifestDispositionEvent event, String message) {
                            synchronized (connectionLifecycleLock) {
                                return executeWithCurrentDispositionPolicy(
                                        event, () -> deny(event.playerId(), event.sessionId(), message))
                                        .orElse(false);
                            }
                        }
                    }, clock, this::isCurrentDispositionPolicy);
            deferredDispositionRoutes = new VelocityDeferredDispositionRoutes(clock);
            deferredAdmissionRoutes = new VelocityDeferredAdmissionRoutes(clock);
            admissionSnapshotCodec = new SignedAdmissionSnapshotCodec(clock, new SecureRandom());
            admissionSigningKey = identity.getPrivate();
            admissionSequence = new AtomicLong(Math.max(1, clock.millis()));
            server.getChannelRegistrar().register(MCAceVelocityChannels.HANDSHAKE);
            server.getChannelRegistrar().register(MCAceVelocityChannels.PAYLOAD);
            server.getChannelRegistrar().register(MCAceVelocityChannels.ADMISSION);
            server.getChannelRegistrar().register(MCAceVelocityChannels.BACKEND_CONTEXT);
            server.getCommandManager().register(
                    server.getCommandManager().metaBuilder("mcacepolicy").plugin(this).build(),
                    new MCAcePolicyCommand(
                            policyManager,
                            identity.getPublic(),
                            clock,
                            logger,
                            dispositionPolicies,
                            dispositionPublisher,
                            dispositionRoutes.effectiveMode()));
            server.getCommandManager().register(
                    server.getCommandManager().metaBuilder("mcaceevidence").plugin(this).build(),
                    new MCAceEvidenceCommand(server, logger, new MCAceEvidenceCommand.Issuer() {
                        @Override
                        public java.util.Optional<com.ellan.mcace.core.evidence.EvidenceRequestRuntime.IssuedRequest> issue(
                                Player player, com.ellan.mcace.core.evidence.EvidenceRequestSpec spec,
                                String operatorId) throws EnvelopeException {
                            synchronized (connectionLifecycleLock) {
                                Optional<VelocityLoginLifecycle.LoginTicket> ticket =
                                        ticketForCurrentPlayerLocked(player);
                                if (ticket.isEmpty()
                                        || coordinator().currentAuthenticatedSessionId(player.getUniqueId()).isEmpty()) {
                                    return Optional.empty();
                                }
                                return coordinator().issueEvidenceRequest(
                                        player.getUniqueId(), spec, operatorId);
                            }
                        }

                        @Override public void cancel(Player player) {
                            synchronized (connectionLifecycleLock) {
                                if (ticketForCurrentPlayerLocked(player).isPresent()) {
                                    coordinator().cancelEvidenceRequest(player.getUniqueId());
                                }
                            }
                        }

                        @Override public boolean isCurrent(Player player) {
                            return currentPhysicalLogin(player).isPresent();
                        }

                        @Override public boolean deliver(Player player, byte[] frame) {
                            synchronized (connectionLifecycleLock) {
                                return ticketForCurrentPlayerLocked(player).isPresent()
                                        && player.sendPluginMessage(MCAceVelocityChannels.HANDSHAKE, frame);
                            }
                        }

                        @Override public EvidenceRequestSpec spec(
                                com.ellan.mcace.protocol.generated.EvidenceCaptureScope scope, String caseId) {
                            com.ellan.mcace.core.evidence.EvidenceContentStore.RetentionDisclosure disclosure =
                                    evidenceContentStore.retentionDisclosure();
                            return disclosure.rawContentRetained()
                                    ? EvidenceRequestSpec.retainedScreenshot(scope, caseId,
                                            com.ellan.mcace.protocol.ProtocolConstants.MAX_EVIDENCE_REQUEST_TTL,
                                            disclosure.retentionSeconds(), disclosure.retentionPolicyId(),
                                            disclosure.retentionPurpose())
                                    : EvidenceRequestSpec.screenshot(scope, caseId);
                        }
                    }, evidenceAdmin, this::issueEvidenceReview));
            server.getCommandManager().register(
                    server.getCommandManager().metaBuilder("mcaceobservation").plugin(this).build(),
                    new MCAceObservationCommand(artifactObservationAudit));
            server.getCommandManager().register(
                    server.getCommandManager().metaBuilder("mcacedisposition").plugin(this).build(),
                    new MCAceDispositionReviewCommand(this::reviewDisposition));
            server.getCommandManager().register(
                    server.getCommandManager().metaBuilder("mcacefederation").plugin(this).build(),
                    new MCAceFederationCommand(federationOperations(), name ->
                            server.getPlayer(name).map(Player::getUniqueId)));
            server.getScheduler().buildTask(this, this::expireHandshakes)
                    .repeat(Duration.ofSeconds(1))
                    .schedule();
            server.getScheduler().buildTask(this, this::pollHeartbeatTransitions)
                    .repeat(Duration.ofSeconds(1))
                    .schedule();
            server.getScheduler().buildTask(this, this::expireFederation)
                    .repeat(Duration.ofSeconds(1))
                    .schedule();
            server.getScheduler().buildTask(this, this::refreshBackendSnapshots)
                    .repeat(BACKEND_REFRESH_INTERVAL)
                    .schedule();
            server.getScheduler().buildTask(this, this::refreshDispositionPolicy)
                    .repeat(DISPOSITION_POLICY_REFRESH_INTERVAL)
                    .schedule();
            server.getScheduler().buildTask(this, () -> {
                        try { evidenceAdmin.sweepExpired(32); }
                        catch (Exception exception) { logger.warn("MCAce evidence retention sweep failed", exception); }
                    })
                    .repeat(Duration.ofMinutes(1))
                    .schedule();
            logger.info("MCAce Phase 2 handshake initialized with enforcement.mode={} effective.mode={}; server key fingerprint={}",
                    admissionConfig.mode(), dispositionRoutes.effectiveMode(), ServerIdentityStore.fingerprint(identity));
            logger.info("MCAce backend/world/game-mode context enabled in shadow-only mode");
            logger.info("Active delegated policy sequence={} trust-sequence={} expires={}",
                    activePolicy.policy().getSequence(), activePolicy.trustSequence(),
                    java.time.Instant.ofEpochMilli(activePolicy.policy().getExpiresAtEpochMs()));
            logDispositionPolicyStatus("initialized", lastDispositionPolicyStatus);
            logger.info("Distribute {} as a pinned public key to trusted MCAce clients",
                    dataDirectory.resolve("identity").resolve("server-public-key.txt"));
        } catch (IOException | EnvelopeException | PolicyException | SecurityPersistenceException exception) {
            if (federationLifecycle != null) {
                federationLifecycle.close();
                federationLifecycle = null;
                federationRuntime = null;
            }
            throw new IllegalStateException("Unable to initialize MCAce", exception);
        }
    }

    private EvidenceReviewEndpointConfiguration loadEvidenceReviewConfiguration() {
        try {
            return EvidenceReviewEndpointConfiguration.loadOrCreate(
                    dataDirectory.resolve(EvidenceReviewEndpointConfiguration.FILE_NAME));
        } catch (IOException exception) {
            logger.warn("MCAce local evidence review disabled because its configuration is invalid", exception);
            return new EvidenceReviewEndpointConfiguration(false, "127.0.0.1", 0, 60, 16);
        }
    }

    private void startEvidenceReview(EvidenceStorageRuntime storage) {
        if (!evidenceReviewConfiguration.enabled()) {
            return;
        }
        java.util.Optional<com.ellan.mcace.core.evidence.EvidenceReviewReader> reader = storage.reviewReader();
        if (reader.isEmpty()) {
            logger.info("MCAce local evidence review remains disabled: storage has no review reader");
            return;
        }
        try {
            evidenceReviewService = LoopbackEvidenceReviewService.start(
                    reader.orElseThrow(), evidenceAuditSink, clock, new SecureRandom(),
                    InetAddress.getByName(evidenceReviewConfiguration.bindAddress()), evidenceReviewConfiguration.port(),
                    Duration.ofSeconds(evidenceReviewConfiguration.tokenTtlSeconds()), evidenceReviewConfiguration.maxTokens());
            logger.info("MCAce local evidence review enabled on loopback; review URLs are console-only");
        } catch (Exception exception) {
            evidenceReviewService = null;
            logger.warn("MCAce local evidence review could not start; proxy operation is unchanged", exception);
        }
    }

    private java.util.Optional<LoopbackEvidenceReviewService.ReviewLink> issueEvidenceReview(
            UUID evidenceId, String operatorId, String reason) {
        LoopbackEvidenceReviewService review = evidenceReviewService;
        if (review == null) {
            return java.util.Optional.empty();
        }
        return java.util.Optional.of(review.issue(evidenceId, operatorId, reason));
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        synchronized (connectionLifecycleLock) {
            challengedPlayers.clear();
            loginLifecycle.clearAll();
        }
        if (evidenceReviewService != null) {
            evidenceReviewService.close();
            evidenceReviewService = null;
        }
        if (asyncAuditSink != null) {
            asyncAuditSink.close();
        }
        if (manifestAuditQueue != null) {
            manifestAuditQueue.close();
        }
        if (artifactObservationAuditQueue != null) {
            artifactObservationAuditQueue.close();
        }
        if (backendContextRuntime != null) {
            backendContextRuntime.close();
            backendContextRuntime = null;
        }
        if (dispositionExecutor != null) {
            for (Player player : server.getAllPlayers()) {
                dispositionExecutor.clear(player.getUniqueId());
            }
        }
        if (deferredDispositionRoutes != null) {
            for (Player player : server.getAllPlayers()) {
                deferredDispositionRoutes.clear(player.getUniqueId());
            }
        }
        if (deferredAdmissionRoutes != null) {
            for (Player player : server.getAllPlayers()) {
                deferredAdmissionRoutes.clear(player.getUniqueId());
                backendReadyBarrier.clear(player.getUniqueId());
            }
        }
        if (federationRuntime != null) {
            for (Player player : server.getAllPlayers()) {
                federationRuntime.removeForPlayer(player.getUniqueId());
            }
            federationRuntime = null;
        }
        if (federationLifecycle != null) {
            federationLifecycle.close();
            federationLifecycle = null;
        }
    }

    @Subscribe
    public void onPostLogin(PostLoginEvent event) {
        Player player = event.getPlayer();
        UUID playerId = player.getUniqueId();
        VelocityLoginLifecycle.LoginTicket ticket;
        Optional<String> retiredSession;
        synchronized (connectionLifecycleLock) {
            if (server.getPlayer(playerId).orElse(null) != player) return;
            // Velocity may publish a replacement before delivering the predecessor Disconnect.
            // Remove the exact old federation grant and coordinator (including pre-auth state)
            // before the replacement ticket becomes visible to any callback.
            retiredSession = removeCoordinatorStateForReplacementLocked(playerId);
            challengedPlayers.remove(playerId);
            ticket = loginLifecycle.beginLogin(playerId, player);
            lastBackendPublish.remove(playerId);
            if (backendContextRuntime != null) backendContextRuntime.clear(playerId);
            if (deferredDispositionRoutes != null) deferredDispositionRoutes.clear(playerId);
            if (deferredAdmissionRoutes != null) deferredAdmissionRoutes.clear(playerId);
            backendReadyBarrier.clear(playerId);
            backendReadyBarrier.resetForLogin(playerId);
        }
        // VelocityDispositionExecutor has its own monitor. Never acquire it while holding the
        // lifecycle lock; callbacks take the executor monitor before entering lifecycle actions.
        if (dispositionExecutor != null) {
            retiredSession.ifPresent(sessionId -> dispositionExecutor.clearSession(playerId, sessionId));
        }
        // Velocity may emit LoginSuccess before the downstream client has entered the
        // play phase.  A plugin message sent in that gap is silently discarded by the
        // vanilla client (the Paper side then waits until the handshake timeout).  Give
        // the play-channel registration a bounded window; onChannelRegister still starts
        // immediately when a client advertises the channel.
        server.getScheduler().buildTask(this, () -> startHandshake(player, ticket))
                .delay(Duration.ofSeconds(5))
                .schedule();
    }

    @Subscribe
    public void onChannelRegister(PlayerChannelRegisterEvent event) {
        if (event.getChannels().contains(MCAceVelocityChannels.HANDSHAKE)) {
            currentPhysicalLogin(event.getPlayer()).ifPresent(login ->
                    startHandshake(login.player(), login.ticket()));
        }
    }

    @Subscribe
    public void onPluginMessage(PluginMessageEvent event) {


        com.ellan.mcace.core.proxy.ProxyAdapterTransportContract.InboundDecision decision =
                MCAceVelocityChannels.inboundDecision(event.getIdentifier(),
                        MCAceVelocityChannels.isPlayerSource(event.getSource()));
        if (decision == com.ellan.mcace.core.proxy.ProxyAdapterTransportContract.InboundDecision.IGNORE) {
            return;
        }
        // Mark both inbound MCAce channels handled before source inspection. A backend must never
        // receive a client-authentication or bounded-payload frame through this proxy.
        event.setResult(PluginMessageEvent.ForwardResult.handled());
        if (decision == com.ellan.mcace.core.proxy.ProxyAdapterTransportContract.InboundDecision.CONSUME_ONLY) {
            return;
        }
        if (decision == com.ellan.mcace.core.proxy.ProxyAdapterTransportContract.InboundDecision.BACKEND_CONTEXT) {
            receiveBackendContext(event);
            return;
        }
        Player player = (Player) event.getSource();
        Optional<PhysicalLogin> physical = currentPhysicalLogin(player);
        if (physical.isEmpty()) return;
        VelocityLoginLifecycle.LoginTicket ticket = physical.orElseThrow().ticket();
        VelocityFederationInboundGate.Decision federationDecision =
                VelocityFederationInboundGate.classify(
                        MCAceVelocityChannels.HANDSHAKE.equals(event.getIdentifier()), event.getData());
        if (federationDecision != VelocityFederationInboundGate.Decision.NOT_FEDERATION) {
            receiveFederation(player, ticket, event.getData(), federationDecision);
            return;
        }
        if (EvidencePacketClassifier.isServerOnlyEvidenceFrame(event.getData())) {
            return;
        }
        if (EvidencePacketClassifier.isEvidenceFrame(event.getData())) {
            EvidenceIngressResult result;
            synchronized (connectionLifecycleLock) {
                if (!isCurrentPhysicalLoginLocked(player, ticket)
                        || !isTicketChallengedLocked(player.getUniqueId(), ticket)) return;
                result = coordinator().receiveEvidence(player.getUniqueId(), event.getData());
            }
            for (byte[] response : result.outboundFrames()) {
                if (!sendHandshakeFrameIfCurrent(player, ticket, response)) return;
            }
            return;
        }
        HandshakeAction action;
        synchronized (connectionLifecycleLock) {
            if (!isCurrentPhysicalLoginLocked(player, ticket)
                    || !isTicketChallengedLocked(player.getUniqueId(), ticket)) return;
            action = coordinator().receive(player.getUniqueId(), event.getData());
        }
        for (byte[] response : action.outboundFrames()) {
            if (!sendHandshakeFrameIfCurrent(player, ticket, response)) return;
        }
        if (!isCurrentPhysicalLogin(player, ticket)) return;
        if (action.protocolViolation()) {
            action.snapshot().ifPresentOrElse(snapshot -> {
                logger.warn("MCAce protocol violation from {}: risk={} band={} (no automatic ban)",
                        player.getUsername(), snapshot.riskScore(), snapshot.riskBand());
                applyAdmission(player, ticket, snapshot);
            }, () -> logger.warn("MCAce rejected heartbeat from {} (monitor-only; admission unchanged)",
                    player.getUsername()));
        } else {
            action.snapshot().filter(PlayerSecuritySnapshot::verified).ifPresent(snapshot ->
                    logger.info("MCAce verified {} at trust={} risk={}",
                            player.getUsername(), snapshot.trustLevel(), snapshot.riskScore()));
        }
        action.snapshot().ifPresent(snapshot -> forwardSnapshot(player, ticket, snapshot));
    }

    @Subscribe
    public void onServerConnected(ServerConnectedEvent event) {
        Optional<PhysicalLogin> physical = currentPhysicalLogin(event.getPlayer());
        if (physical.isEmpty()) return;
        PhysicalLogin login = physical.orElseThrow();
        server.getScheduler().buildTask(this, () -> {
                    if (!isCurrentPhysicalLogin(login.player(), login.ticket())) return;
                    api.snapshot(login.player().getUniqueId())
                            .ifPresent(snapshot -> forwardSnapshot(login.player(), login.ticket(), snapshot));
                })
                .delay(Duration.ofMillis(100))
                .schedule();
    }

    @Subscribe
    public void onServerPreConnect(ServerPreConnectEvent event) {
        synchronized (connectionLifecycleLock) {
            Optional<VelocityLoginLifecycle.LoginTicket> ticket = ticketForCurrentPlayerLocked(event.getPlayer());
            if (ticket.isEmpty()) return;
            backendReadyBarrier.beginConnection(event.getPlayer().getUniqueId());
        }
    }

    /** The first completed backend connection is the only point at which a deferred route retries. */
    @Subscribe
    public void onServerPostConnect(ServerPostConnectEvent event) {
        Player player = event.getPlayer();
        UUID playerId = player.getUniqueId();
        VelocityLoginLifecycle.LoginTicket ticket;
        long generation;
        synchronized (connectionLifecycleLock) {
            Optional<VelocityLoginLifecycle.LoginTicket> current = ticketForCurrentPlayerLocked(player);
            if (current.isEmpty()) return;
            ticket = current.orElseThrow();
            generation = backendReadyBarrier.markReady(playerId);
        }
        if (generation == 0L) return;
        server.getScheduler().buildTask(this,
                () -> retryDeferredDispositionRoute(player, ticket, generation)).schedule();
        server.getScheduler().buildTask(this,
                () -> retryDeferredAdmissionRoute(player, ticket, generation)).schedule();
    }

    @Subscribe
    public void onDisconnect(DisconnectEvent event) {
        Player player = event.getPlayer();
        UUID playerId = player.getUniqueId();
        VelocityLoginLifecycle.LoginTicket ticket;
        Optional<String> retiredSession;
        synchronized (connectionLifecycleLock) {
            Optional<VelocityLoginLifecycle.LoginTicket> captured = loginLifecycle.ticketFor(playerId, player);
            Player mapped = server.getPlayer(playerId).orElse(null);
            if (captured.isEmpty() || (mapped != null && mapped != player)) return;
            ticket = captured.orElseThrow();
            retiredSession = removeCoordinatorStateForReplacementLocked(playerId);
            removeTicketBoundChallenge(challengedPlayers, playerId, ticket);
            if (!loginLifecycle.clear(playerId, player, ticket)) return;
            lastBackendPublish.remove(playerId);
            if (backendContextRuntime != null) backendContextRuntime.clear(playerId);
            if (deferredDispositionRoutes != null) deferredDispositionRoutes.clear(playerId);
            if (deferredAdmissionRoutes != null) deferredAdmissionRoutes.clear(playerId);
            backendReadyBarrier.clear(playerId);
        }
        if (dispositionExecutor != null) {
            retiredSession.ifPresent(sessionId -> dispositionExecutor.clearSession(playerId, sessionId));
        }
        scheduleCleanupReadiness(playerId, player, ticket,
                new VelocityLoginCleanupReadiness(System.nanoTime()));
    }

    public InMemoryMCAceApi api() {
        return api;
    }

    /** Returns the version-one, read-only SDK bridge using JDK types only. */
    public java.util.function.Function<java.util.Map<String, Object>, java.util.Map<String, Object>>
            mcaceInteropV1() {
        return com.ellan.mcace.sdk.MCAceInteropExports.from(api);
    }

    private void expireHandshakes() {
        if (backendContextRuntime != null) backendContextRuntime.expire();
        for (PlayerSecuritySnapshot snapshot : coordinator().expireTimedOut()) {
            Player player = server.getPlayer(snapshot.playerId()).orElse(null);
            Optional<PhysicalLogin> login = player == null ? Optional.empty() : currentPhysicalLogin(player);
            if (login.isPresent() && api.snapshot(snapshot.playerId()).filter(snapshot::equals).isPresent()) {
                PhysicalLogin current = login.orElseThrow();
                logger.info("MCAce timed out for {}; session is LIMITED", player.getUsername());
                applyAdmission(player, current.ticket(), snapshot);
                forwardSnapshot(player, current.ticket(), snapshot);
            }
        }
    }

    private void pollHeartbeatTransitions() {
        for (HeartbeatTransition transition : coordinator().pollHeartbeatTransitions()) {
            if (currentAuthenticatedLogin(transition.playerId(), transition.sessionId()).isEmpty()) continue;
            logger.info("MCAce heartbeat player={} session={} {}->{} (monitor-only; admission unchanged)",
                    transition.playerId(), transition.sessionId(), transition.previous(), transition.current());
        }
        for (HeartbeatMissingTransition transition : coordinator().pollHeartbeatMissingTransitions(
                admissionConfig.heartbeatMissing().toPolicy())) {
            applyHeartbeatMissingTransition(transition);
        }
    }

    private void expireFederation() {
        FederationRuntime runtime = federationRuntime;
        if (runtime != null) {
            runtime.expire(256);
        }
    }

    private MCAceFederationCommand.Operations federationOperations() {
        return new MCAceFederationCommand.Operations() {
            @Override public com.ellan.mcace.core.federation.FederationRuntimeState status() {
                return federation().status();
            }

            @Override public java.util.List<String> peers() {
                return federation().peerSummaries().stream()
                        .map(peer -> peer.networkId() + " capabilities=" + peer.capabilities())
                        .toList();
            }

            @Override public FederationRuntimeStatus issue(
                    UUID playerId, String targetNetworkId, String operatorId) {
                synchronized (connectionLifecycleLock) {
                    Player player = server.getPlayer(playerId).orElse(null);
                    Optional<VelocityLoginLifecycle.LoginTicket> ticket = player == null
                            ? Optional.empty() : ticketForCurrentPlayerLocked(player);
                    Optional<FederationSubject> subject = ticket.isEmpty()
                            ? Optional.empty() : coordinator().federationSubject(playerId);
                    if (subject.isEmpty() || !coordinator().isCurrentAuthenticatedSession(
                            playerId, subject.orElseThrow().authenticatedSessionId())) {
                        return FederationRuntimeStatus.NO_CURRENT_SUBJECT;
                    }
                    FederationIssueResult issued = federation().issueConsent(
                            subject.orElseThrow(), targetNetworkId, operatorId);
                    if (issued.outboundFrame().isEmpty()) return issued.status();
                    boolean sent;
                    try {
                        sent = isCurrentPhysicalLoginLocked(player, ticket.orElseThrow())
                                && player.sendPluginMessage(
                                        MCAceVelocityChannels.HANDSHAKE, issued.outboundFrame().orElseThrow());
                    } catch (RuntimeException exception) {
                        sent = false;
                    }
                    if (!sent) {
                        federation().cancelPending(playerId, subject.orElseThrow().authenticatedSessionId());
                        return FederationRuntimeStatus.INVALID_FRAME;
                    }
                    return issued.status();
                }
            }
        };
    }

    private void receiveFederation(
            Player player,
            VelocityLoginLifecycle.LoginTicket ticket,
            byte[] frame,
            VelocityFederationInboundGate.Decision decision) {
        if (decision == VelocityFederationInboundGate.Decision.DROP_SERVER_ONLY) {
            return;
        }
        synchronized (connectionLifecycleLock) {
            if (!isCurrentPhysicalLoginLocked(player, ticket)
                    || !isTicketChallengedLocked(player.getUniqueId(), ticket)) return;
            Optional<FederationSubject> subject = coordinator().federationSubject(player.getUniqueId());
            if (subject.isEmpty() || !coordinator().isCurrentAuthenticatedSession(
                    player.getUniqueId(), subject.orElseThrow().authenticatedSessionId())) {
                logger.info("MCAce federation frame ignored for {}: no current local VERIFIED session",
                        player.getUsername());
                return;
            }
            try {
                if (decision == VelocityFederationInboundGate.Decision.CONSENT_RESPONSE) {
                    FederationGrantResult result = federation().receiveConsentResponse(subject.orElseThrow(), frame);
                    if (result.outboundFrame().isPresent()) {
                        boolean sent = isCurrentPhysicalLoginLocked(player, ticket)
                                && player.sendPluginMessage(
                                        MCAceVelocityChannels.HANDSHAKE, result.outboundFrame().orElseThrow());
                        if (!sent) {
                            logger.info("MCAce federation grant delivery unavailable for {}", player.getUsername());
                        }
                    }
                    logger.info("MCAce federation consent response status={} player={}",
                            result.status(), player.getUniqueId());
                    return;
                }
                if (decision == VelocityFederationInboundGate.Decision.PRESENTATION) {
                    FederationPresentationResult result = federation().receivePresentation(
                            subject.orElseThrow(), frame, "velocity-client:" + player.getUniqueId());
                    logger.info("MCAce federation presentation status={} player={} (observation-only)",
                            result.status(), player.getUniqueId());
                }
            } catch (RuntimeException exception) {
                logger.warn("MCAce rejected a federation frame from {}", player.getUsername(), exception);
            }
        }
    }

    private FederationRuntime federation() {
        return Objects.requireNonNull(federationRuntime, "federation runtime");
    }

    private void applyHeartbeatMissingTransition(HeartbeatMissingTransition transition) {
        Optional<PhysicalLogin> current = currentAuthenticatedLogin(
                transition.playerId(), transition.sessionId());
        if (current.isEmpty()) return;
        PhysicalLogin login = current.orElseThrow();
        Player player = login.player();
        if (transition.kind() == HeartbeatMissingTransition.Kind.RECOVER) {
            synchronized (connectionLifecycleLock) {
                if (!isCurrentAuthenticatedLoginLocked(player, login.ticket(), transition.sessionId())) return;
                player.sendMessage(Component.text(
                        "MCAce: heartbeat recovered; temporary session control cleared."));
            }
            logger.info("MCAce heartbeat temporary control recovered player={} action={} (no forced return route)",
                    transition.playerId(), transition.action());
            return;
        }
        if (transition.action() == com.ellan.mcace.core.session.HeartbeatMissingPolicy.Action.NOTICE) {
            synchronized (connectionLifecycleLock) {
                if (!isCurrentAuthenticatedLoginLocked(player, login.ticket(), transition.sessionId())) return;
                player.sendMessage(Component.text(
                        "MCAce: heartbeat missing; this verified session is being monitored."));
            }
            logger.info("MCAce heartbeat missing notice player={} polls={}", transition.playerId(), transition.missingPolls());
            return;
        }
        if (dispositionRoutes.effectiveMode() == VelocityAdmissionConfig.Mode.LIMITED_ROUTE) {
            synchronized (connectionLifecycleLock) {
                if (!isCurrentAuthenticatedLoginLocked(player, login.ticket(), transition.sessionId())) return;
                deferredDispositionRoutes.resetForCurrentSession(
                        transition.playerId(), transition.sessionId(), login.ticket(), player);
            }
            boolean routed = routeDisposition(
                    transition.playerId(), transition.sessionId(), com.ellan.mcace.core.disposition.DispositionAction.LIMIT);
            logger.info("MCAce heartbeat missing temporary route player={} polls={} routed={}",
                    transition.playerId(), transition.missingPolls(), routed);
        } else {
            logger.info("MCAce heartbeat missing route configured but global LIMITED_ROUTE is disabled; player={} monitor-only",
                    transition.playerId());
        }
    }

    private void refreshBackendSnapshots() {
        Instant refreshBefore = clock.instant().minus(BACKEND_REFRESH_INTERVAL);
        for (Player player : server.getAllPlayers()) {
            Optional<PhysicalLogin> login = currentPhysicalLogin(player);
            if (login.isEmpty()) continue;
            Instant lastPublished = lastBackendPublish.get(player.getUniqueId());
            if (lastPublished == null || !lastPublished.isAfter(refreshBefore)) {
                api.snapshot(player.getUniqueId()).ifPresent(snapshot ->
                        forwardSnapshot(player, login.orElseThrow().ticket(), snapshot));
            }
        }
    }

    /** Refreshes the separate detection-disposition policy only; this method has no admission side effect. */
    private void refreshDispositionPolicy() {
        VelocityDispositionPolicyStatus previous = lastDispositionPolicyStatus;
        VelocityDispositionPolicyStatus current = dispositionPolicies.refresh();
        lastDispositionPolicyStatus = current;
        if (previous == null
                || previous.refreshStatus() != current.refreshStatus()
                || !previous.activeSequence().equals(current.activeSequence())
                || previous.sourceAvailable() != current.sourceAvailable()) {
            logDispositionPolicyStatus("refreshed", current);
        }
    }

    private void logDispositionPolicyStatus(String event, VelocityDispositionPolicyStatus status) {
        logger.info("MCAce disposition policy {}: status={} sequence={} source={} available={}",
                event,
                status.refreshStatus(),
                status.activeSequence().map(Object::toString).orElse("none"),
                status.path(),
                status.sourceAvailable());
        if (status.refreshStatus() != ProxyPolicyRefreshStatus.ACTIVE) {
            logger.warn("MCAce disposition policy is observation-only until a valid signed policy is available");
        }
    }

    /** Queue saturation or evaluation failure is audit-only and cannot affect a verified session. */
    private void enqueueManifestAudit(com.ellan.mcace.core.session.AuthenticatedManifest manifest) {

        if (backendContextRuntime != null) backendContextRuntime.rememberManifest(manifest);
        if (!manifestAuditQueue.offer(manifest)) {
            logger.warn("MCAce manifest audit queue is saturated; audit was dropped without changing admission");
        }
    }

    private void auditAuthenticatedManifest(com.ellan.mcace.core.session.AuthenticatedManifest manifest) {
        AuthenticatedManifestAuditResult audit = manifestEvaluator.evaluate(
                manifest,
                new EvaluationContext(
                        manifest.playerId(), "velocity", null, null, null, Set.of(), clock.instant()));
        AuthenticatedManifestDispositionEvent event = audit.dispositionEvent();
        logger.info("MCAce manifest audit: player={} observations={} actions={} advisoryBlocks={} policyVersion={} issues={} status={} truncated={}",
                audit.playerId(),
                audit.evaluation().totalObservations(),
                audit.evaluation().actionCounts(),
                audit.evaluation().advisoryEnforcementRuleBlocks(),
                event.activePolicyVersion().orElse("none"),
                audit.consistencyIssues().size(),
                audit.evaluation().refreshStatus(),
                audit.evaluation().truncated());
        // The audit worker carries only immutable content-free data across this handoff. Player
        // lookup and all connection mutations happen in the Velocity scheduler task.
        server.getScheduler().buildTask(this, () -> executeDisposition(event)).schedule();
    }

    /**
     * Dynamic updates are evaluated by the same signed policy as the initial manifest.  The
     * resulting event is still tagged CLIENT_REPORTED by the core, so WARN/NOTICE/CHALLENGE can
     * execute automatically while LIMIT/QUARANTINE/DENY remain gated on independent server
     * authority.  This closes the runtime resource-pack/Mod change path without treating a client
     * claim as a server-confirmed cheat verdict.
     */
    private void enqueueArtifactObservationAudit(com.ellan.mcace.core.session.AuthenticatedManifest manifest) {
        if (backendContextRuntime != null) backendContextRuntime.rememberManifest(manifest);
        if (!artifactObservationAuditQueue.offer(manifest)) {
            logger.warn("MCAce artifact observation audit queue is saturated; update dropped without changing admission");
        }
    }

    private void auditArtifactObservationUpdate(com.ellan.mcace.core.session.AuthenticatedManifest manifest) {
        AuthenticatedManifestAuditResult audit = manifestEvaluator.evaluate(manifest,
                new EvaluationContext(manifest.playerId(), "velocity", null, null, null, Set.of(), clock.instant()));
        AuthenticatedManifestDispositionEvent event = audit.dispositionEvent();
        logger.info("MCAce artifact observation audit: player={} observations={} actions={} issues={} status={} selectedResourcePacks={} selectedShaderPacks={}",
                audit.playerId(), audit.evaluation().totalObservations(), audit.evaluation().actionCounts(),
                audit.consistencyIssues().size(), audit.evaluation().refreshStatus(),
                manifest.request().getSelectedResourcePacksList(),
                manifest.request().getSelectedShaderPacksList());
        artifactObservationAudit.append(new ArtifactObservationAuditRecord(
                audit.playerId(), manifest.authenticatedAt(), clock.instant(), audit.evaluation().totalObservations(),
                audit.consistencyIssues().size(), audit.evaluation().actionCounts(), audit.evaluation().refreshStatus()));
        // Keep this handoff content-free and session-bound; executeDisposition repeats the current
        // login, admission, route and policy checks on the Velocity scheduler thread.
        server.getScheduler().buildTask(this, () -> executeDisposition(event)).schedule();
    }

    private MCAceDispositionReviewCommand.ReviewResult reviewDisposition(
            String playerName,
            String operatorId,
            AdministratorDispositionReviewRequest request) {
        TrustedDispositionAuthorizationRuntime authorizations = trustedDispositionAuthorizations;
        if (authorizations == null) {
            return MCAceDispositionReviewCommand.ReviewResult.status(
                    MCAceDispositionReviewCommand.Status.AUTHORIZATION_AUDIT_UNAVAILABLE);
        }
        Player player = server.getPlayer(playerName).orElse(null);
        if (player == null) {
            return MCAceDispositionReviewCommand.ReviewResult.status(
                    MCAceDispositionReviewCommand.Status.UNKNOWN_PLAYER);
        }
        String sessionId;
        String backendId;
        synchronized (connectionLifecycleLock) {
            Optional<VelocityLoginLifecycle.LoginTicket> ticket = ticketForCurrentPlayerLocked(player);
            Optional<String> session = coordinator().currentAuthenticatedSessionId(player.getUniqueId());
            boolean verified = api.snapshot(player.getUniqueId())
                    .map(snapshot -> snapshot.verified()
                            && snapshot.admissionStatus() == AdmissionStatus.VERIFIED)
                    .orElse(false);
            if (ticket.isEmpty() || session.isEmpty() || !verified
                    || !coordinator().isCurrentAuthenticatedSession(
                    player.getUniqueId(), session.orElseThrow())) {
                return MCAceDispositionReviewCommand.ReviewResult.status(
                        MCAceDispositionReviewCommand.Status.NO_CURRENT_AUTHENTICATED_SESSION);
            }
            sessionId = session.orElseThrow();
            backendId = player.getCurrentServer()
                    .map(connection -> connection.getServerInfo().getName()).orElse(null);
        }
        AuthenticatedManifestDispositionEvent event;
        try {
            event = authorizations.authorizeAdministratorReview(
                    player.getUniqueId(), sessionId,
                    new EvaluationContext(
                            player.getUniqueId(), "velocity", backendId, null, null, Set.of(), clock.instant()),
                    request.observation(), operatorId, request.reviewTicket());
            logger.info("MCAce trusted disposition authorization persisted: authorization={} "
                            + "journal-durable=true execution-context-bound=true "
                            + "player={} action={} policy-sequence={}",
                    event.authorizationId().orElseThrow(), event.playerId(), event.highestAction(),
                    event.activePolicySequence().orElseThrow());
        } catch (IOException | RuntimeException exception) {
            logger.warn("MCAce administrator-reviewed disposition authorization failed closed: {}",
                    exception.getClass().getSimpleName());
            return MCAceDispositionReviewCommand.ReviewResult.status(
                    MCAceDispositionReviewCommand.Status.FAILED);
        }
        try {
            server.getScheduler().buildTask(this, () -> executeDisposition(event)).schedule();
        } catch (RuntimeException exception) {
            logger.warn("MCAce administrator-reviewed disposition execution queue is unavailable");
            return MCAceDispositionReviewCommand.ReviewResult.status(
                    MCAceDispositionReviewCommand.Status.EXECUTION_QUEUE_UNAVAILABLE);
        }
        return new MCAceDispositionReviewCommand.ReviewResult(
                MCAceDispositionReviewCommand.Status.AUTHORIZED,
                Optional.of(event.highestAction()), event.winningRuleId(),
                event.activePolicySequence(), event.authorizationId());
    }
    private void executeDisposition(AuthenticatedManifestDispositionEvent event) {
        Optional<PhysicalLogin> before = currentAuthenticatedLogin(event.playerId(), event.sessionId());
        long eventGeneration = 0L;
        if (before.isPresent()) {
            PhysicalLogin login = before.orElseThrow();
            synchronized (connectionLifecycleLock) {
                if (isCurrentAuthenticatedLoginLocked(login.player(), login.ticket(), event.sessionId())) {
                    eventGeneration = backendReadyBarrier.generation(event.playerId());
                    deferredDispositionRoutes.resetForCurrentSession(
                            event.playerId(), event.sessionId(), login.ticket(), login.player());
                }
            }
        }
        VelocityDispositionExecutor.Result result = dispositionExecutor.apply(event);
        if (result.status() == VelocityDispositionExecutor.Status.DEFERRED_ROUTE) {
            String target = dispositionRoutes.targetFor(event.highestAction()).orElse(null);
            VelocityDeferredDispositionRoutes.DeferResult deferred;
            synchronized (connectionLifecycleLock) {
                Optional<PhysicalLogin> current = currentAuthenticatedLoginLocked(
                        event.playerId(), event.sessionId());
                if (before.isEmpty() || current.isEmpty()
                        || current.orElseThrow().player() != before.orElseThrow().player()
                        || !current.orElseThrow().ticket().equals(before.orElseThrow().ticket())) {
                    deferred = VelocityDeferredDispositionRoutes.DeferResult.STALE_SESSION_REJECTED;
                } else if (target == null) {
                    deferred = VelocityDeferredDispositionRoutes.DeferResult.CAPACITY_REJECTED;
                } else {
                    PhysicalLogin login = current.orElseThrow();
                    deferred = deferredDispositionRoutes.defer(
                            event, target, eventGeneration, login.ticket(), login.player());
                }
            }
            logger.info("MCAce manifest disposition: action={} result=DEFERRED player={} queue={} authorization={} "
                            + "session-bound=true execution-context-bound={}",
                    result.action(), event.playerId(), deferred,
                    event.authorizationId().map(Object::toString).orElse("none"),
                    event.authorizationContextCommitmentSha256().isPresent());
            return;
        }
        if (result.status() != VelocityDispositionExecutor.Status.OBSERVE) {
            logger.info("MCAce manifest disposition: action={} result={} player={} authorization={} "
                            + "session-bound=true execution-context-bound={}",
                    result.action(), result.status(), event.playerId(),
                    event.authorizationId().map(Object::toString).orElse("none"),
                    event.authorizationContextCommitmentSha256().isPresent());
        }
    }

    private boolean isCurrentDispositionPolicy(AuthenticatedManifestDispositionEvent event) {
        if (dispositionPolicies == null
                || event.activePolicyVersion().isEmpty()
                || event.activePolicySequence().isEmpty()
                || event.activePolicyExpiresAt().isEmpty()
                || event.winningRuleId().isEmpty()) {
            return false;
        }
        return dispositionPolicies.coreRuntime().isCurrentActivePolicy(
                event.activePolicyVersion().orElseThrow(),
                event.activePolicySequence().orElseThrow(),
                event.activePolicyExpiresAt().orElseThrow(),
                event.winningRuleId().orElseThrow(),
                event.highestAction());
    }

    private <T> Optional<T> executeWithCurrentDispositionPolicy(
            AuthenticatedManifestDispositionEvent event,
            java.util.function.Supplier<T> operation) {
        if (dispositionPolicies == null
                || event.activePolicyVersion().isEmpty()
                || event.activePolicySequence().isEmpty()
                || event.activePolicyExpiresAt().isEmpty()
                || event.winningRuleId().isEmpty()) {
            return Optional.empty();
        }
        if (!Thread.holdsLock(connectionLifecycleLock)
                || !currentAuthorizationContextMatchesLocked(event)) {
            return Optional.empty();
        }
        return dispositionPolicies.coreRuntime().executeIfCurrentActivePolicy(
                event.activePolicyVersion().orElseThrow(),
                event.activePolicySequence().orElseThrow(),
                event.activePolicyExpiresAt().orElseThrow(),
                event.winningRuleId().orElseThrow(), event.highestAction(), operation);
    }

    /** Call only while holding the physical-login lifecycle boundary. */
    private boolean currentAuthorizationContextMatchesLocked(
            AuthenticatedManifestDispositionEvent event) {
        if (!Thread.holdsLock(connectionLifecycleLock)
                || event.authorizationId().isEmpty()
                || event.authorizationContextCommitmentSha256().isEmpty()) {
            return false;
        }
        Optional<PhysicalLogin> current = currentAuthenticatedLoginLocked(
                event.playerId(), event.sessionId());
        boolean verified = api.snapshot(event.playerId())
                .map(snapshot -> snapshot.verified()
                        && snapshot.admissionStatus() == AdmissionStatus.VERIFIED)
                .orElse(false);
        if (current.isEmpty() || !verified || !backendReadyBarrier.isReady(event.playerId())) {
            return false;
        }
        Player player = current.orElseThrow().player();
        String backend = player.getCurrentServer()
                .map(connection -> connection.getServerInfo().getName()).orElse(null);
        EvaluationContext context = new EvaluationContext(
                event.playerId(), "velocity", backend, null, null, Set.of(), clock.instant());
        return TrustedDispositionCommitments.executionContextMatches(
                event.authorizationId().orElseThrow(), context,
                event.authorizationContextCommitmentSha256().orElseThrow());
    }

    /** All guards are repeated because the original audit was asynchronous and Velocity handoffs may overlap. */
    private void retryDeferredDispositionRoute(
            Player player, VelocityLoginLifecycle.LoginTicket ticket, long generation) {
        if (deferredDispositionRoutes == null) return;
        UUID playerId = player.getUniqueId();
        Optional<VelocityDeferredDispositionRoutes.Pending> claimed;
        synchronized (connectionLifecycleLock) {
            if (!isCurrentPhysicalLoginLocked(player, ticket)) return;
            claimed = deferredDispositionRoutes.claimForPostConnect(
                    playerId, generation, ticket, player);
        }
        if (claimed.isEmpty()) return;
        VelocityDeferredDispositionRoutes.Pending pending = claimed.orElseThrow();
        AuthenticatedManifestDispositionEvent event = pending.event();
        if (!isCurrentAuthenticatedLogin(player, ticket, event.sessionId())) {
            logger.info("MCAce deferred disposition route result=FAIL player={} reason=stale-session", playerId);
            return;
        }
        synchronized (connectionLifecycleLock) {
            if (!isCurrentAuthenticatedLoginLocked(player, ticket, event.sessionId())) return;
            deferredDispositionRoutes.resetForCurrentSession(
                    playerId, event.sessionId(), ticket, player);
        }
        boolean verified = api.snapshot(playerId)
                .map(snapshot -> snapshot.verified() && snapshot.admissionStatus() == AdmissionStatus.VERIFIED)
                .orElse(false);
        if (!verified) {
            logger.info("MCAce deferred disposition route result=FAIL player={} reason=admission", playerId);
            return;
        }
        String effectiveTarget = dispositionRoutes.targetFor(event.highestAction()).orElse(null);
        if (dispositionRoutes.effectiveMode() != VelocityAdmissionConfig.Mode.LIMITED_ROUTE
                || dispositionRoutes.validationStatus() != VelocityDispositionRoutes.ValidationStatus.ACTIVE
                || !pending.targetName().equals(effectiveTarget)) {
            logger.info("MCAce deferred disposition route result=FAIL player={} reason=inactive-route", playerId);
            return;
        }
        if (!isCurrentAuthenticatedLogin(player, ticket, event.sessionId())
                || !backendReadyBarrier.isReady(playerId, generation)) {
            logger.info("MCAce deferred disposition route result=FAIL player={} reason=backend-not-ready", playerId);
            return;
        }
        VelocityDispositionExecutor.Result result = dispositionExecutor.apply(event);
        logger.info("MCAce deferred disposition route retry: action={} result={} player={} authorization={} "
                        + "target-bound=true execution-context-bound={}",
                result.action(), result.status(), playerId,
                event.authorizationId().map(Object::toString).orElse("none"),
                event.authorizationContextCommitmentSha256().isPresent());
    }

    private void retryDeferredAdmissionRoute(
            Player player, VelocityLoginLifecycle.LoginTicket ticket, long generation) {
        if (deferredAdmissionRoutes == null) return;
        UUID playerId = player.getUniqueId();
        Optional<VelocityDeferredAdmissionRoutes.Entry> claimed;
        synchronized (connectionLifecycleLock) {
            if (!isCurrentPhysicalLoginLocked(player, ticket)) return;
            claimed = deferredAdmissionRoutes.claim(playerId, generation, ticket, player);
        }
        if (claimed.isEmpty()) return;
        String sessionId = claimed.orElseThrow().sessionId();
        if (!isCurrentAuthenticatedLogin(player, ticket, sessionId)) {
            logger.info("MCAce deferred baseline route result=FAIL player={} reason=stale-session", playerId);
            return;
        }
        if (!backendReadyBarrier.isReady(playerId, generation)) return;
        PlayerSecuritySnapshot snapshot = api.snapshot(playerId).orElse(null);
        if (!isCurrentAuthenticatedLogin(player, ticket, sessionId)
                || snapshot == null || snapshot.admissionStatus() != AdmissionStatus.LIMITED
                || dispositionRoutes.effectiveMode() != VelocityAdmissionConfig.Mode.LIMITED_ROUTE
                || dispositionRoutes.validationStatus() != VelocityDispositionRoutes.ValidationStatus.ACTIVE) {
            logger.info("MCAce deferred baseline route result=FAIL player={} reason=stale-or-inactive", playerId);
            return;
        }
        VelocityDispositionExecutor.RouteOutcome outcome = routeDispositionOutcome(
                playerId, sessionId, com.ellan.mcace.core.disposition.DispositionAction.LIMIT);
        logger.info("MCAce deferred baseline route retry result={} player={}", outcome, playerId);
    }

    private void forwardSnapshot(
            Player player, VelocityLoginLifecycle.LoginTicket ticket, PlayerSecuritySnapshot snapshot) {
        if (!isCurrentPhysicalLogin(player, ticket)) return;
        player.getCurrentServer().ifPresent(connection -> {
            try {
                long transportSequence = nextAdmissionSequence();
                SignedAdmissionSnapshotCodec.SignedAdmissionSnapshot signed =
                        admissionSnapshotCodec.signWithExpiry(
                        snapshot,
                        BACKEND_SNAPSHOT_TTL,
                        transportSequence,
                        admissionSigningKey);
                if (!isCurrentPhysicalLogin(player, ticket)) return;
                ShadowBackendContextRuntime contextRuntime = backendContextRuntime;
                if (contextRuntime != null) {
                    coordinator().currentAuthenticatedSessionId(player.getUniqueId()).ifPresent(sessionId ->
                            contextRuntime.expectBackend(
                                    player.getUniqueId(), sessionId,
                                    connection.getServerInfo().getName(),
                                    transportSequence, signed.expiresAt()));
                }
                if (connection.sendPluginMessage(MCAceVelocityChannels.ADMISSION, signed.encodedFrame())
                        && isCurrentPhysicalLogin(player, ticket)) {
                    lastBackendPublish.put(player.getUniqueId(), clock.instant());
                } else {
                    logger.debug("MCAce backend admission channel is unavailable for {}", player.getUsername());
                }
            } catch (EnvelopeException exception) {
                logger.error("Could not sign MCAce backend admission snapshot for {}", player.getUsername(), exception);
            }
        });
    }

    private void receiveBackendContext(PluginMessageEvent event) {
        ShadowBackendContextRuntime runtime = backendContextRuntime;
        if (runtime == null || !(event.getSource() instanceof ServerConnection connection)
                || !(event.getTarget() instanceof Player player) || connection.getPlayer() != player) {
            return;
        }
        ShadowBackendContextRuntime.ReceiveResult result;
        synchronized (connectionLifecycleLock) {
            Optional<VelocityLoginLifecycle.LoginTicket> ticket = ticketForCurrentPlayerLocked(player);
            if (ticket.isEmpty()
                    || coordinator().currentAuthenticatedSessionId(player.getUniqueId()).isEmpty()) {
                return;
            }
            // A backend can answer before Velocity publishes it through getCurrentServer(). The
            // exact authenticated session, backend id and admission sequence remain fail-closed
            // inside ShadowBackendContextRuntime, so early or stale connections cannot bind.
            result = runtime.receive(
                    player.getUniqueId(), connection.getServerInfo().getName(), event.getData());
        }
        if (result.acceptedContext().isPresent()) {
            logger.debug("MCAce accepted backend context for {} status={} (shadow-only)",
                    player.getUsername(), result.status());
        } else {
            logger.warn("MCAce rejected backend context for {} status={} (admission unchanged)",
                    player.getUsername(), result.status());
        }
    }

    private long nextAdmissionSequence() {
        return admissionSequence.updateAndGet(
                previous -> Math.max(Math.incrementExact(previous), Math.max(1, clock.millis())));
    }

    private void startHandshake(Player player, VelocityLoginLifecycle.LoginTicket ticket) {
        synchronized (connectionLifecycleLock) {
            UUID playerId = player.getUniqueId();
            if (!isCurrentPhysicalLoginLocked(player, ticket)
                    || !installTicketBoundChallenge(challengedPlayers, playerId, ticket)) return;
            try {
                byte[] challenge = coordinator().begin(playerId);
                boolean sent = isCurrentPhysicalLoginLocked(player, ticket)
                        && player.sendPluginMessage(MCAceVelocityChannels.HANDSHAKE, challenge);
                logger.info("MCAce challenge dispatch player={} bytes={} sent={}",
                        player.getUsername(), challenge.length, sent);
                if (!sent) {
                    removeTicketBoundChallenge(challengedPlayers, playerId, ticket);
                    coordinator().remove(playerId);
                    logger.debug("MCAce challenge channel is not available for {}", player.getUsername());
                }
            } catch (EnvelopeException | PolicyException exception) {
                removeTicketBoundChallenge(challengedPlayers, playerId, ticket);
                coordinator().remove(playerId);
                logger.error("Could not create MCAce challenge for {}", player.getUsername(), exception);
            }
        }
    }

    private record PhysicalLogin(Player player, VelocityLoginLifecycle.LoginTicket ticket) {
        private PhysicalLogin {
            Objects.requireNonNull(player, "player");
            Objects.requireNonNull(ticket, "ticket");
        }
    }

    private Optional<PhysicalLogin> currentPhysicalLogin(Player player) {
        synchronized (connectionLifecycleLock) {
            return ticketForCurrentPlayerLocked(player).map(ticket -> new PhysicalLogin(player, ticket));
        }
    }

    private Optional<PhysicalLogin> currentAuthenticatedLogin(UUID playerId, String sessionId) {
        synchronized (connectionLifecycleLock) {
            return currentAuthenticatedLoginLocked(playerId, sessionId);
        }
    }

    private Optional<PhysicalLogin> currentAuthenticatedLoginLocked(UUID playerId, String sessionId) {
        Player player = server.getPlayer(Objects.requireNonNull(playerId, "playerId")).orElse(null);
        if (player == null) return Optional.empty();
        Optional<VelocityLoginLifecycle.LoginTicket> ticket = ticketForCurrentPlayerLocked(player);
        return ticket.isPresent() && coordinator().isCurrentAuthenticatedSession(playerId, sessionId)
                ? Optional.of(new PhysicalLogin(player, ticket.orElseThrow())) : Optional.empty();
    }

    private Optional<VelocityLoginLifecycle.LoginTicket> ticketForCurrentPlayerLocked(Player player) {
        Objects.requireNonNull(player, "player");
        UUID playerId = player.getUniqueId();
        if (server.getPlayer(playerId).orElse(null) != player) return Optional.empty();
        return loginLifecycle.ticketFor(playerId, player);
    }

    private boolean isCurrentPhysicalLogin(Player player, VelocityLoginLifecycle.LoginTicket ticket) {
        synchronized (connectionLifecycleLock) {
            return isCurrentPhysicalLoginLocked(player, ticket);
        }
    }

    private boolean isCurrentPhysicalLoginLocked(
            Player player, VelocityLoginLifecycle.LoginTicket ticket) {
        return server.getPlayer(player.getUniqueId()).orElse(null) == player
                && loginLifecycle.isCurrent(player.getUniqueId(), player, ticket);
    }

    private boolean isCurrentAuthenticatedLogin(
            Player player, VelocityLoginLifecycle.LoginTicket ticket, String sessionId) {
        synchronized (connectionLifecycleLock) {
            return isCurrentAuthenticatedLoginLocked(player, ticket, sessionId);
        }
    }

    private boolean isCurrentAuthenticatedLoginLocked(
            Player player, VelocityLoginLifecycle.LoginTicket ticket, String sessionId) {
        return isCurrentPhysicalLoginLocked(player, ticket)
                && coordinator().isCurrentAuthenticatedSession(player.getUniqueId(), sessionId);
    }

    /**
     * Route-state suppliers already hold their own monitor, so they may not enter the lifecycle
     * monitor (DENY takes those locks in the opposite direction). These three thread-safe reads
     * still bind the operation to the captured player, ticket, and authenticated session.
     */
    private boolean isCurrentAuthenticatedLoginSnapshot(
            Player player, VelocityLoginLifecycle.LoginTicket ticket, String sessionId) {
        return server.getPlayer(player.getUniqueId()).orElse(null) == player
                && loginLifecycle.isCurrent(player.getUniqueId(), player, ticket)
                && coordinator().isCurrentAuthenticatedSession(player.getUniqueId(), sessionId);
    }

    private boolean isTicketChallengedLocked(
            UUID playerId, VelocityLoginLifecycle.LoginTicket ticket) {
        return ticket.equals(challengedPlayers.get(playerId));
    }

    static boolean installTicketBoundChallenge(
            Map<UUID, VelocityLoginLifecycle.LoginTicket> challenges,
            UUID playerId,
            VelocityLoginLifecycle.LoginTicket ticket) {
        return Objects.requireNonNull(challenges, "challenges").putIfAbsent(
                Objects.requireNonNull(playerId, "playerId"), Objects.requireNonNull(ticket, "ticket")) == null;
    }

    static boolean removeTicketBoundChallenge(
            Map<UUID, VelocityLoginLifecycle.LoginTicket> challenges,
            UUID playerId,
            VelocityLoginLifecycle.LoginTicket ticket) {
        return Objects.requireNonNull(challenges, "challenges").remove(
                Objects.requireNonNull(playerId, "playerId"), Objects.requireNonNull(ticket, "ticket"));
    }

    private boolean sendHandshakeFrameIfCurrent(
            Player player, VelocityLoginLifecycle.LoginTicket ticket, byte[] frame) {
        synchronized (connectionLifecycleLock) {
            return isCurrentPhysicalLoginLocked(player, ticket)
                    && player.sendPluginMessage(MCAceVelocityChannels.HANDSHAKE, frame);
        }
    }

    /** Callers hold the lifecycle lock; this always drops a pre-auth coordinator as well. */
    private Optional<String> removeCoordinatorStateForReplacementLocked(UUID playerId) {
        if (handshakes == null) return Optional.empty();
        Optional<String> authenticatedSession = coordinator().currentAuthenticatedSessionId(playerId);
        if (federationRuntime != null) {
            coordinator().federationSubject(playerId).ifPresent(subject ->
                    federationRuntime.removeForSession(playerId, subject.authenticatedSessionId()));
        }
        coordinator().remove(playerId);
        return authenticatedSession;
    }

    private void scheduleCleanupReadiness(
            UUID playerId,
            Player player,
            VelocityLoginLifecycle.LoginTicket ticket,
            VelocityLoginCleanupReadiness readiness) {
        try {
            server.getScheduler().buildTask(this,
                    () -> pollCleanupReadiness(playerId, player, ticket, readiness))
                    .delay(VelocityLoginCleanupReadiness.POLL_INTERVAL)
                    .schedule();
        } catch (RuntimeException exception) {
            logger.info(VelocityLoginCleanupReadiness.TIMEOUT_MARKER);
        }
    }

    private void pollCleanupReadiness(
            UUID playerId,
            Player player,
            VelocityLoginLifecycle.LoginTicket ticket,
            VelocityLoginCleanupReadiness readiness) {
        boolean exactTicketCleared = !loginLifecycle.isCurrent(playerId, player, ticket);
        boolean proxyPlayerAbsent = server.getPlayer(playerId).isEmpty();
        VelocityLoginCleanupReadiness.Outcome outcome = readiness.poll(
                System.nanoTime(), exactTicketCleared, proxyPlayerAbsent);
        if (outcome == VelocityLoginCleanupReadiness.Outcome.PENDING) {
            scheduleCleanupReadiness(playerId, player, ticket, readiness);
            return;
        }
        logger.info(VelocityLoginCleanupReadiness.marker(outcome));
    }

    static boolean consumeRouteCompletion(AtomicBoolean completionReported) {
        return Objects.requireNonNull(completionReported, "completionReported").compareAndSet(false, true);
    }

    private ServerHandshakeCoordinator coordinator() {
        return Objects.requireNonNull(handshakes, "MCAce handshake coordinator is not initialized");
    }

    private SecurityAuditSink configureAuditStorage(KeyPair identity, Clock clock)
            throws SecurityPersistenceException {
        VelocityAdmissionConfig.StorageConfig storage = admissionConfig.storage();
        if (!storage.enabled()) {
            logger.info("MCAce PostgreSQL audit storage is disabled");
            return SecurityAuditSink.noop();
        }
        String password = System.getenv(storage.passwordEnvironmentVariable());
        if (password == null || password.isEmpty()) {
            throw new SecurityPersistenceException(
                    "PostgreSQL password environment variable is missing: "
                            + storage.passwordEnvironmentVariable());
        }
        javax.sql.DataSource dataSource = PostgresDataSources.create(
                storage.jdbcUrl(), storage.username(), password);
        if (storage.migrateOnStart()) {
            PostgresSchemaMigrator.migrate(dataSource);
        }
        PostgresSecurityAuditRepository repository = new PostgresSecurityAuditRepository(
                dataSource,
                new Ed25519EvidenceChainSigner(identity.getPrivate(), identity.getPublic()),
                clock);
        asyncAuditSink = new AsyncSecurityAuditSink(repository, 4096, this::logPersistenceFailure);
        logger.info("MCAce PostgreSQL audit storage initialized at {}", redactJdbcUrl(storage.jdbcUrl()));
        return asyncAuditSink;
    }

    private void logPersistenceFailure(Exception exception) {
        logger.error("MCAce audit persistence failed; player admission was not changed", exception);
    }

    private static String redactJdbcUrl(String jdbcUrl) {
        int query = jdbcUrl.indexOf('?');
        return query < 0 ? jdbcUrl : jdbcUrl.substring(0, query) + "?<redacted>";
    }

    private void applyAdmission(
            Player player, VelocityLoginLifecycle.LoginTicket ticket, PlayerSecuritySnapshot snapshot) {
        if (!isCurrentPhysicalLogin(player, ticket)) return;
        if (snapshot.admissionStatus() != com.ellan.mcace.sdk.AdmissionStatus.LIMITED
                || dispositionRoutes.effectiveMode() != VelocityAdmissionConfig.Mode.LIMITED_ROUTE) {
            return;
        }
        UUID playerId = player.getUniqueId();
        coordinator().currentAuthenticatedSessionId(playerId).ifPresent(sessionId -> {
            if (!isCurrentAuthenticatedLogin(player, ticket, sessionId)) return;
            long sessionGeneration = backendReadyBarrier.generation(playerId);
            synchronized (connectionLifecycleLock) {
                if (!isCurrentAuthenticatedLoginLocked(player, ticket, sessionId)) return;
                deferredDispositionRoutes.resetForCurrentSession(
                        playerId, sessionId, ticket, player);
            }
            VelocityDispositionExecutor.RouteOutcome outcome = routeDispositionOutcome(
                    playerId, sessionId, com.ellan.mcace.core.disposition.DispositionAction.LIMIT);
            boolean stillCurrentSession = isCurrentAuthenticatedLogin(player, ticket, sessionId);
            if (outcome == VelocityDispositionExecutor.RouteOutcome.DEFERRED
                    && stillCurrentSession && deferredAdmissionRoutes != null) {
                boolean queued;
                synchronized (connectionLifecycleLock) {
                    queued = isCurrentAuthenticatedLoginLocked(player, ticket, sessionId)
                            && deferredAdmissionRoutes.defer(
                                    playerId, sessionId, sessionGeneration, ticket, player);
                }
                logger.info("MCAce baseline disposition route result=DEFERRED player={} queue={}", playerId, queued);
            }
        });
    }

    private boolean routeDisposition(
            UUID playerId, String sessionId, com.ellan.mcace.core.disposition.DispositionAction action) {
        return routeDispositionOutcome(playerId, sessionId, action)
                == VelocityDispositionExecutor.RouteOutcome.DISPATCHED;
    }

    private VelocityDispositionExecutor.RouteOutcome routeDispositionOutcome(
            UUID playerId, String sessionId, com.ellan.mcace.core.disposition.DispositionAction action) {
        return routeDispositionOutcome(playerId, sessionId, action, Optional.empty());
    }

    private VelocityDispositionExecutor.RouteOutcome routeDispositionOutcome(
            UUID playerId, String sessionId,
            com.ellan.mcace.core.disposition.DispositionAction action,
            Optional<UUID> authorizationId) {
        if (deferredDispositionRoutes == null) {
            return VelocityDispositionExecutor.RouteOutcome.UNAVAILABLE;
        }
        Optional<PhysicalLogin> current = currentAuthenticatedLogin(playerId, sessionId);
        if (current.isEmpty()) return VelocityDispositionExecutor.RouteOutcome.UNAVAILABLE;
        PhysicalLogin login = current.orElseThrow();
        return deferredDispositionRoutes.executeIfPermitted(
                playerId, sessionId, login.ticket(), login.player(),
                () -> routeDispositionPermitted(login, sessionId, action, authorizationId));
    }

    /** Called under the route-state lock; it may only initiate a Velocity request, never wait. */
    private VelocityDispositionExecutor.RouteOutcome routeDispositionPermitted(
            PhysicalLogin login,
            String sessionId,
            com.ellan.mcace.core.disposition.DispositionAction action,
            Optional<UUID> authorizationId) {
        Player player = login.player();
        UUID playerId = player.getUniqueId();
        if (!isCurrentAuthenticatedLoginSnapshot(player, login.ticket(), sessionId)) {
            return VelocityDispositionExecutor.RouteOutcome.UNAVAILABLE;
        }
        if (dispositionRoutes.effectiveMode() != VelocityAdmissionConfig.Mode.LIMITED_ROUTE) {
            return VelocityDispositionExecutor.RouteOutcome.UNAVAILABLE;
        }
        String targetName = dispositionRoutes.targetFor(action).orElse(null);
        if (targetName == null) {
            return VelocityDispositionExecutor.RouteOutcome.UNAVAILABLE;
        }
        var target = server.getServer(targetName).orElse(null);
        if (target == null) {
            return VelocityDispositionExecutor.RouteOutcome.UNAVAILABLE;
        }
        if (!backendReadyBarrier.isReady(playerId)) {
            return VelocityDispositionExecutor.RouteOutcome.DEFERRED;
        }
        boolean alreadyThere = player.getCurrentServer()
                .map(connection -> connection.getServerInfo().equals(target.getServerInfo()))
                .orElse(false);
        if (!alreadyThere) {
            try {
                if (!isCurrentAuthenticatedLoginSnapshot(player, login.ticket(), sessionId)) {
                    return VelocityDispositionExecutor.RouteOutcome.UNAVAILABLE;
                }
                AtomicBoolean completionReported = new AtomicBoolean();
                player.createConnectionRequest(target).connect().whenComplete((result, failure) -> {
                    if (!consumeRouteCompletion(completionReported)) return;
                    server.getScheduler().buildTask(this, () -> {
                            if (!isCurrentAuthenticatedLogin(player, login.ticket(), sessionId)) return;
                            if (failure != null || result == null || !result.isSuccessful()) {
                                logger.info("MCAce manifest disposition route result=FAIL player={} action={} target={} "
                                                + "authorization={} execution-context-bound={}",
                                        playerId, action, targetName,
                                        authorizationId.map(Object::toString).orElse("none"),
                                        authorizationId.isPresent());
                            } else {
                                logger.info("MCAce manifest disposition route result=SUCCESS player={} action={} target={} status={} "
                                                + "authorization={} execution-context-bound={}",
                                        playerId, action, targetName, result.getStatus(),
                                        authorizationId.map(Object::toString).orElse("none"),
                                        authorizationId.isPresent());
                            }
                        }).schedule();
                });
            } catch (RuntimeException exception) {
                logger.info("MCAce manifest disposition route result=FAIL player={} action={} target={} "
                                + "authorization={} execution-context-bound={}",
                        playerId, action, targetName,
                        authorizationId.map(Object::toString).orElse("none"), authorizationId.isPresent());
                return VelocityDispositionExecutor.RouteOutcome.UNAVAILABLE;
            }
        } else {
            logger.info("MCAce manifest disposition route result=SUCCESS player={} action={} target={} "
                            + "already-current=true authorization={} execution-context-bound={}",
                    playerId, action, targetName,
                    authorizationId.map(Object::toString).orElse("none"), authorizationId.isPresent());
        }
        logger.info("MCAce manifest disposition route result=DISPATCHED player={} action={} target={} "
                        + "authorization={} execution-context-bound={}",
                playerId, action, targetName,
                authorizationId.map(Object::toString).orElse("none"), authorizationId.isPresent());
        return VelocityDispositionExecutor.RouteOutcome.DISPATCHED;
    }
}
