package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.admission.SignedAdmissionSnapshotCodec;
import com.ellan.mcace.core.evidence.EvidenceReviewEndpointConfiguration;
import com.ellan.mcace.core.federation.FederationGrantResult;
import com.ellan.mcace.core.federation.FederationIssueResult;
import com.ellan.mcace.core.federation.FederationPresentationResult;
import com.ellan.mcace.core.federation.FederationRuntime;
import com.ellan.mcace.core.federation.FederationRuntimeState;
import com.ellan.mcace.core.federation.FederationRuntimeStatus;
import com.ellan.mcace.core.federation.FederationSubject;
import com.ellan.mcace.core.proxy.ProxyPolicyRefreshStatus;
import com.ellan.mcace.core.proxy.SharedProxyDispositionPolicyRuntime;
import com.ellan.mcace.core.proxy.ShadowBackendContextRuntime;
import com.ellan.mcace.core.proxy.ArtifactObservationAuditSink;
import com.ellan.mcace.core.proxy.FileArtifactObservationAuditSink;
import com.ellan.mcace.core.proxy.AdministratorDispositionReviewRequest;
import com.ellan.mcace.core.proxy.FileTrustedDispositionAuthorizationSink;
import com.ellan.mcace.core.proxy.TrustedDispositionAuthorizationRuntime;
import com.ellan.mcace.core.proxy.TrustedDispositionCommitments;
import com.ellan.mcace.core.disposition.EvaluationContext;
import com.ellan.mcace.core.session.HeartbeatTransition;
import com.ellan.mcace.core.session.HeartbeatMissingTransition;
import com.ellan.mcace.core.session.HeartbeatMissingPolicy;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.sdk.MCAceApi;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.connection.Server;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.event.PluginMessageEvent;
import net.md_5.bungee.api.event.PlayerDisconnectEvent;
import net.md_5.bungee.api.event.PlayerConfigurationEvent;
import net.md_5.bungee.api.event.PostLoginEvent;
import net.md_5.bungee.api.event.ServerConnectedEvent;
import net.md_5.bungee.api.event.ServerConnectEvent;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.api.scheduler.ScheduledTask;
import net.md_5.bungee.event.EventHandler;
import net.md_5.bungee.event.EventPriority;

/**
 * BungeeCord transport adapter for MCAce sessions.
 *
 * <p>This plugin intentionally does not contain a separate risk engine or ban logic. A provider
 * supplies the shared-core session bridge, and downstream plugins must pin the proxy signing
 * identity before accepting the short-lived signed admission snapshots forwarded here.</p>
 */
public final class MCAceBungeePlugin extends Plugin implements Listener {
    private static final Duration BACKEND_SNAPSHOT_TTL = Duration.ofSeconds(15);
    private static final long BACKEND_REFRESH_SECONDS = 5L;
    private static final long DISPOSITION_REFRESH_SECONDS = 300L;

    /** A challenge belongs to one physical login ticket, never merely to a UUID. */
    private final Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challengedPlayers =
            new ConcurrentHashMap<>();
    /**
     * Records the sole configuration-phase start attempt for an exact physical login. This is
     * deliberately separate from {@link #challengedPlayers}: a failed hello send must make later
     * duplicate configuration callbacks inert, without permitting inbound protocol frames.
     */
    private final Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> configurationStartAttempts =
            new ConcurrentHashMap<>();
    /** Terminal timeouts retain a ticket-local no-retry marker after the armed/attempt maps clear. */
    private final Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> terminalConfigurationTickets =
            new ConcurrentHashMap<>();
    /** Guarded by {@link #connectionLifecycleLock}; never resolve a UUID-only replacement here. */
    private final Map<UUID, AuthenticatedPhysicalSession> authenticatedPhysicalSessions = new HashMap<>();
    private BungeeSessionBridge bridge;
    private ScheduledTask expiryTask;
    private ScheduledTask refreshTask;
    private ScheduledTask dispositionRefreshTask;
    private ScheduledTask evidenceSweepTask;
    private SignedAdmissionSnapshotCodec admissionSnapshotCodec;
    private PrivateKey admissionSigningKey;
    private AtomicLong admissionSequence;
    private Clock clock;
    private AtomicReference<BungeeDispositionStatus> dispositionStatus;
    private BungeeDispositionExecutor dispositionExecutor;
    private TrustedDispositionAuthorizationRuntime trustedDispositionAuthorizations;
    private BungeeDeferredDispositionRoutes deferredDispositionRoutes;
    /** Serializes plugin-owned connection identity with bridge mutations across Bungee async events. */
    private final Object connectionLifecycleLock = new Object();
    private Optional<BungeeDispositionRouteTargets> dispositionRouteTargets = Optional.empty();
    private volatile BungeeDispositionExecutionMode effectiveDispositionMode =
            BungeeDispositionExecutionMode.MONITOR;
    private EvidenceReviewEndpointConfiguration evidenceReviewConfiguration;
    private ShadowBackendContextRuntime backendContextRuntime;

    @Override
    public void onEnable() {
        evidenceReviewConfiguration = loadEvidenceReviewConfiguration();
        bridge = discoverBridge(getDataFolder().toPath());
        clock = Clock.systemUTC();
        deferredDispositionRoutes = new BungeeDeferredDispositionRoutes(clock);
        admissionSnapshotCodec = new SignedAdmissionSnapshotCodec(clock, new SecureRandom());
        admissionSigningKey = bridge.admissionSigningKey().orElse(null);
        backendContextRuntime = bridge.shadowBackendContextRuntime().orElse(null);
        admissionSequence = new AtomicLong(Math.max(1L, clock.millis()));
        dispositionStatus = new AtomicReference<>(BungeeDispositionStatus.unavailable());
        try {
            trustedDispositionAuthorizations = bridge.dispositionPolicyRuntime()
                    .map(runtime -> {
                        try {
                            return new TrustedDispositionAuthorizationRuntime(
                                    runtime,
                                    new FileTrustedDispositionAuthorizationSink(
                                            getDataFolder().toPath().resolve(
                                                    "trusted-disposition-authorizations.log"),
                                            8L * 1024 * 1024));
                        } catch (java.io.IOException exception) {
                            return null;
                        }
                    }).orElse(null);
        } catch (RuntimeException exception) {
            trustedDispositionAuthorizations = null;
        }
        if (trustedDispositionAuthorizations == null) {
            getLogger().warning("MCAce administrator-reviewed disposition is disabled because its durable audit is unavailable");
        }
        BungeeDispositionExecutor executor = createDispositionExecutor(bridge);
        dispositionExecutor = executor;
        bridge.setDispositionEventHandler(event -> {
            if (!executor.offer(event)) {
                getLogger().warning("MCAce disposition event queue saturated or closed; event dropped");
            }
        });
        getProxy().registerChannel(BungeeMCAceChannels.HANDSHAKE);
        getProxy().registerChannel(BungeeMCAceChannels.ADMISSION);
        getProxy().registerChannel(BungeeMCAceChannels.PAYLOAD);
        getProxy().registerChannel(BungeeMCAceChannels.BACKEND_CONTEXT);
        getProxy().getPluginManager().registerListener(this, this);
        getProxy().getPluginManager().registerCommand(
                this, new MCAceBungeeCommand(
                        bridge.api(), dispositionStatus::get, this::dispositionPublisher,
                        () -> effectiveDispositionMode));
        getProxy().getPluginManager().registerCommand(this,
                new MCAceEvidenceCommand(() -> bridge, this::dispatchEvidenceRequest));
        getProxy().getPluginManager().registerCommand(
                this, new MCAceDispositionReviewCommand(this::reviewDisposition));
        try {
            getProxy().getPluginManager().registerCommand(this, new MCAceObservationCommand(
                    new FileArtifactObservationAuditSink(getDataFolder().toPath().resolve("artifact-observation-audit.log"),
                            8L * 1024 * 1024)));
        } catch (java.io.IOException exception) {
            getLogger().warning("MCAce dynamic observation audit view disabled: " + safeMessage(exception));
            getProxy().getPluginManager().registerCommand(this,
                    new MCAceObservationCommand(ArtifactObservationAuditSink.noop()));
        }
        getProxy().getPluginManager().registerCommand(this, new MCAceFederationCommand(
                federationOperations(), name -> java.util.Optional.ofNullable(getProxy().getPlayer(name))
                        .map(ProxiedPlayer::getUniqueId)));
        expiryTask = getProxy().getScheduler().schedule(this, this::expireSessions, 1, 1, TimeUnit.SECONDS);
        refreshTask = getProxy().getScheduler().schedule(
                this, this::refreshBackendSnapshots,
                BACKEND_REFRESH_SECONDS, BACKEND_REFRESH_SECONDS, TimeUnit.SECONDS);
        evidenceSweepTask = getProxy().getScheduler().schedule(this, this::sweepEvidence, 60, 60, TimeUnit.SECONDS);
        bridge.dispositionPolicyRuntime().ifPresent(runtime -> {
            refreshDispositionPolicy(runtime);
            dispositionRefreshTask = getProxy().getScheduler().schedule(
                    this, this::refreshDispositionPolicy,
                    DISPOSITION_REFRESH_SECONDS, DISPOSITION_REFRESH_SECONDS, TimeUnit.SECONDS);
        });
        getLogger().info("MCAce BungeeCord adapter enabled; session bridge="
                + bridge.getClass().getSimpleName());
        if (admissionSigningKey == null) {
            getLogger().warning("MCAce backend admission forwarding is disabled because the bridge has no signing key");
        }
    }

    private EvidenceReviewEndpointConfiguration loadEvidenceReviewConfiguration() {
        try {
            return EvidenceReviewEndpointConfiguration.loadOrCreate(
                    getDataFolder().toPath().resolve(EvidenceReviewEndpointConfiguration.FILE_NAME));
        } catch (java.io.IOException exception) {
            getLogger().warning("MCAce local evidence review disabled because its configuration is invalid");
            return new EvidenceReviewEndpointConfiguration(false, "127.0.0.1", 0, 60, 16);
        }
    }

    @Override
    public void onDisable() {
        if (expiryTask != null) {
            expiryTask.cancel();
            expiryTask = null;
        }
        if (refreshTask != null) {
            refreshTask.cancel();
            refreshTask = null;
        }
        if (dispositionRefreshTask != null) {
            dispositionRefreshTask.cancel();
            dispositionRefreshTask = null;
        }
        if (evidenceSweepTask != null) {
            evidenceSweepTask.cancel();
            evidenceSweepTask = null;
        }
        challengedPlayers.clear();
        configurationStartAttempts.clear();
        terminalConfigurationTickets.clear();
        synchronized (connectionLifecycleLock) {
            authenticatedPhysicalSessions.clear();
        }
        if (bridge != null) {
            bridge.federationRuntime().ifPresent(runtime -> getProxy().getPlayers().forEach(
                    player -> runtime.removeForPlayer(player.getUniqueId())));
        }
        if (dispositionExecutor != null) {
            dispositionExecutor.close();
        }
        dispositionExecutor = null;
        if (deferredDispositionRoutes != null) {
            deferredDispositionRoutes = null;
        }
        dispositionRouteTargets = Optional.empty();
        effectiveDispositionMode = BungeeDispositionExecutionMode.MONITOR;
        getProxy().unregisterChannel(BungeeMCAceChannels.HANDSHAKE);
        getProxy().unregisterChannel(BungeeMCAceChannels.ADMISSION);
        getProxy().unregisterChannel(BungeeMCAceChannels.PAYLOAD);
        getProxy().unregisterChannel(BungeeMCAceChannels.BACKEND_CONTEXT);
        if (bridge != null) {
            try {
                bridge.close();
            } catch (Exception exception) {
                getLogger().warning("MCAce session bridge close failed: " + safeMessage(exception));
            }
            bridge = null;
        }
        admissionSigningKey = null;
        admissionSnapshotCodec = null;
        admissionSequence = null;
        backendContextRuntime = null;
        dispositionStatus = null;
        clock = null;
    }

    private void sweepEvidence() {
        bridge.evidenceAdmin().ifPresent(admin -> {
            try { admin.sweepExpired(32); }
            catch (Exception exception) { getLogger().warning("MCAce evidence retention sweep failed"); }
        });
    }

    /**
     * Starts a visible-client evidence request only for the captured current physical login.
     * Bungee has no send acknowledgement, so a successful result means dispatch initiated only.
     */
    private BungeeEvidenceDispatch.Result dispatchEvidenceRequest(
            ProxiedPlayer capturedPlayer,
            com.ellan.mcace.protocol.generated.EvidenceCaptureScope scope,
            String caseId,
            String operatorId) {
        Objects.requireNonNull(capturedPlayer, "capturedPlayer");
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(caseId, "caseId");
        Objects.requireNonNull(operatorId, "operatorId");
        synchronized (connectionLifecycleLock) {
            UUID playerId = capturedPlayer.getUniqueId();
            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
            BungeeSessionBridge current = bridge;
            Optional<BungeeDeferredDispositionRoutes.LoginTicket> ticket = routes == null
                    ? Optional.empty() : routes.ticketFor(playerId, capturedPlayer);
            Optional<String> sessionId = current == null ? Optional.empty()
                    : current.currentAuthenticatedSessionId(playerId);
            if (routes == null || current == null || ticket.isEmpty() || sessionId.isEmpty()
                    || !isCurrentAuthenticatedPhysicalSession(
                            capturedPlayer, ticket.orElseThrow(), current, sessionId.orElseThrow())) {
                return BungeeEvidenceDispatch.Result.unavailable();
            }
            BungeeDeferredDispositionRoutes.LoginTicket capturedTicket = ticket.orElseThrow();
            String capturedSession = sessionId.orElseThrow();
            return BungeeEvidenceDispatch.dispatch(new BungeeEvidenceDispatch.Endpoint() {
                @Override
                public boolean isCurrent() {
                    return getProxy().getPlayer(playerId) == capturedPlayer
                            && isCurrentAuthenticatedPhysicalSession(
                                    capturedPlayer, capturedTicket, current, capturedSession);
                }

                @Override
                public Optional<com.ellan.mcace.core.evidence.EvidenceRequestRuntime.IssuedRequest> issue()
                        throws com.ellan.mcace.protocol.crypto.EnvelopeException {
                    return current.issueEvidenceRequest(
                            playerId, current.evidenceRequestSpec(scope, caseId), operatorId);
                }

                @Override
                public boolean cancelOutstanding() {
                    // Core permits one outstanding request per player; the surrounding exact
                    // physical-login/session gate ensures this can only cancel the issued session.
                    return current.cancelEvidenceRequest(playerId);
                }

                @Override
                public void send(byte[] frame) {
                    capturedPlayer.sendData(BungeeMCAceChannels.HANDSHAKE, frame);
                }
            });
        }
    }

    @EventHandler
    public void onPostLogin(PostLoginEvent event) {
        ProxiedPlayer player = event.getPlayer();
        Optional<String> departingSession;
        synchronized (connectionLifecycleLock) {
            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
            if (routes == null) {
                return;
            }
            // A same-UUID replacement can arrive before the old disconnect event. Remove the
            // predecessor bridge state while the lifecycle lock prevents either connection from
            // processing a frame, then publish the new physical-login ticket.
            departingSession = removeBridgeSessionForReplacement(bridge, player.getUniqueId());
            authenticatedPhysicalSessions.remove(player.getUniqueId());
            replaceTicketBoundChallenge(challengedPlayers, player.getUniqueId());
            replaceTicketBoundChallenge(configurationStartAttempts, player.getUniqueId());
            replaceTicketBoundChallenge(terminalConfigurationTickets, player.getUniqueId());
            routes.beginLogin(player.getUniqueId(), player);
        }
        clearDepartingDispositionSession(player.getUniqueId(), departingSession);
    }

    /**
     * Bungee's LOGIN configuration callback is the only initial-handshake trigger. It tells this
     * adapter that Bungee/backend configuration handling has completed; it does not assert that
     * a raw client peer has reached Mojang's wire-level CONFIGURATION state. The raw-peer
     * three-stage acceptance probe remains the runtime acceptance gate. In particular, PostLogin
     * has no safe custom-payload send point and ServerConnected is already too late (or may
     * describe an ordinary backend switch).
     */
    @EventHandler
    public void onPlayerConfiguration(PlayerConfigurationEvent event) {
        if (!isInitialConfigurationReason(event.getReason())) {
            return;
        }
        ProxiedPlayer player = event.getPlayer();
        BungeeDeferredDispositionRoutes.LoginTicket ticket;
        synchronized (connectionLifecycleLock) {
            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
            if (routes == null) {
                return;
            }
            Optional<BungeeDeferredDispositionRoutes.LoginTicket> current =
                    routes.ticketFor(player.getUniqueId(), player);
            if (current.isEmpty() || !isCurrentPhysicalLogin(player, current.orElseThrow())
                    || !mayStartConfigurationHandshake(
                            challengedPlayers, configurationStartAttempts, terminalConfigurationTickets, player.getUniqueId(),
                            current.orElseThrow())) {
                return;
            }
            ticket = current.orElseThrow();
        }
        // Do not schedule this callback: the frame must be emitted while Bungee is still in the
        // LOGIN configuration phase. startHandshake rechecks every exact identity/ticket guard.
        startHandshake(player, ticket);
    }

    @EventHandler
    public void onPluginMessage(PluginMessageEvent event) {
        BungeeInboundFrameGate.Decision decision = BungeeInboundFrameGate.decide(
                event.getTag(), event.getSender() instanceof ProxiedPlayer);
        if (decision == BungeeInboundFrameGate.Decision.IGNORE) {
            return;
        }
        // MCAce channels terminate at the proxy. Never relay backend- or client-originated
        // authority frames across this boundary.
        event.setCancelled(true);
        if (decision == BungeeInboundFrameGate.Decision.CONSUME_ONLY) {
            return;
        }
        if (decision == BungeeInboundFrameGate.Decision.BACKEND_CONTEXT) {
            receiveBackendContext(event);
            return;
        }
        ProxiedPlayer player = (ProxiedPlayer) event.getSender();
        if (!isCurrentPhysicalLogin(player)) {
            return;
        }
        synchronized (connectionLifecycleLock) {
            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
            Optional<BungeeDeferredDispositionRoutes.LoginTicket> ticket = routes == null
                    ? Optional.empty() : routes.ticketFor(player.getUniqueId(), player);
            if (ticket.isEmpty() || !mayProcessConfigurationBoundFrame(
                    isCurrentPhysicalLogin(player, ticket.orElseThrow()), challengedPlayers,
                    player.getUniqueId(), ticket.orElseThrow())) {
                return;
            }
        }
        BungeeFederationInboundGate.Decision federationDecision =
                BungeeFederationInboundGate.classify(
                        BungeeMCAceChannels.HANDSHAKE.equals(event.getTag()), event.getData());
        if (federationDecision != BungeeFederationInboundGate.Decision.NOT_FEDERATION) {
            receiveFederation(player, event.getData(), federationDecision);
            return;
        }
        synchronized (connectionLifecycleLock) {
            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
            Optional<BungeeDeferredDispositionRoutes.LoginTicket> ticket = routes == null
                    ? Optional.empty() : routes.ticketFor(player.getUniqueId(), player);
            if (ticket.isEmpty() || !mayProcessConfigurationBoundFrame(
                    isCurrentPhysicalLogin(player, ticket.orElseThrow()), challengedPlayers,
                    player.getUniqueId(), ticket.orElseThrow())) {
                return;
            }
            try {
                BungeeBridgeAction action = activeBridge().receive(player.getUniqueId(), event.getData());
                dispatchBridgeAction(player, ticket.orElseThrow(), activeBridge(), action);
            } catch (RuntimeException exception) {
                getLogger().warning("MCAce rejected a malformed handshake frame from " + player.getName()
                        + ": " + safeMessage(exception));
                return;
            }
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onServerConnect(ServerConnectEvent event) {
        synchronized (connectionLifecycleLock) {
            ProxiedPlayer player = event.getPlayer();
            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
            if (routes == null || !isCurrentPhysicalLogin(player)) {
                return;
            }
            routes.ticketFor(player.getUniqueId(), player).ifPresent(ticket ->
                    routes.markBackendConnecting(player.getUniqueId(), player, ticket));
        }
    }

    @EventHandler
    public void onServerConnected(ServerConnectedEvent event) {
        ProxiedPlayer player = event.getPlayer();
        BungeeDeferredDispositionRoutes.LoginTicket ticket;
        synchronized (connectionLifecycleLock) {
            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
            if (routes == null) {
                return;
            }
            if (!isCurrentPhysicalLogin(player)) {
                return;
            }
            Optional<BungeeDeferredDispositionRoutes.LoginTicket> marked =
                    routes.markBackendReady(player.getUniqueId(), player);
            if (marked.isEmpty()) {
                return;
            }
            ticket = marked.orElseThrow();
            BungeeSessionBridge current = bridge;
            if (current != null) {
                current.currentAuthenticatedSessionId(player.getUniqueId()).ifPresent(sessionId ->
                        current.api().snapshot(player.getUniqueId()).ifPresent(snapshot -> {
                            if (isCurrentAuthenticatedPhysicalSession(player, ticket, current, sessionId)) {
                                bindAuthenticatedPhysicalSession(player, ticket, sessionId);
                                forwardSnapshot(player, ticket, sessionId, current, snapshot);
                            }
                        }));
            }
        }
        getProxy().getScheduler().schedule(
                this, () -> retryDeferredDispositionRoute(player, ticket), 0, TimeUnit.MILLISECONDS);
    }

    @EventHandler
    public void onPlayerDisconnect(PlayerDisconnectEvent event) {
        ProxiedPlayer player = event.getPlayer();
        UUID playerId = player.getUniqueId();
        Optional<String> departingSession;
        synchronized (connectionLifecycleLock) {
            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
            Optional<BungeeDeferredDispositionRoutes.LoginTicket> ticket = routes == null
                    ? Optional.empty() : routes.ticketFor(playerId, player);
            if (ticket.isEmpty()) {
                return;
            }
            if (!routes.clear(playerId, player, ticket.orElseThrow())) {
                return;
            }
            removeTicketBoundChallenge(challengedPlayers, playerId, ticket.orElseThrow());
            removeTicketBoundChallenge(configurationStartAttempts, playerId, ticket.orElseThrow());
            removeTicketBoundChallenge(terminalConfigurationTickets, playerId, ticket.orElseThrow());
            authenticatedPhysicalSessions.remove(playerId);
            departingSession = removeBridgeSessionForReplacement(bridge, playerId);
        }
        clearDepartingDispositionSession(playerId, departingSession);
    }

    /** Exposes read-only state to an embedding Bungee plugin. */
    public MCAceApi api() {
        return activeBridge().api();
    }

    /** Returns the version-one, read-only SDK bridge using JDK types only. */
    public java.util.function.Function<java.util.Map<String, Object>, java.util.Map<String, Object>>
            mcaceInteropV1() {
        return com.ellan.mcace.sdk.MCAceInteropExports.from(activeBridge().api());
    }

    private void startHandshake(ProxiedPlayer player, BungeeDeferredDispositionRoutes.LoginTicket ticket) {
        Objects.requireNonNull(player, "player");
        Objects.requireNonNull(ticket, "ticket");
        Optional<String> departingSession = Optional.empty();
        synchronized (connectionLifecycleLock) {
            UUID playerId = player.getUniqueId();
            if (!isCurrentPhysicalLogin(player, ticket)
                    || !mayStartConfigurationHandshake(
                            challengedPlayers, configurationStartAttempts, terminalConfigurationTickets, playerId, ticket)) {
                return;
            }
            // Mark the sole attempt before begin() so a duplicate LOGIN callback cannot race a
            // second core begin(). Inbound-frame permission is deliberately installed only after
            // begin() supplies a real hello frame.
            configurationStartAttempts.put(playerId, ticket);
            try {
                Optional<byte[]> initialFrame = activeBridge().begin(playerId);
                if (initialFrame.isEmpty()) {
                    // A bridge that cannot produce hello has not begun a usable protocol session.
                    // Keep only the one-shot attempt marker, revoke inbound permission, and
                    // retire the exact bridge state before any duplicate callback can arrive.
                    departingSession = retireUnsentConfigurationHandshake(
                            challengedPlayers, bridge, playerId, ticket);
                } else if (installTicketBoundChallenge(challengedPlayers, playerId, ticket)) {
                    player.sendData(BungeeMCAceChannels.HANDSHAKE, initialFrame.orElseThrow());
                } else {
                    // A configuration challenge must never be overwritten. This is fail-closed
                    // even though the lifecycle lock makes it an internal consistency failure.
                    departingSession = removeBridgeSessionForReplacement(bridge, playerId);
                }
            } catch (RuntimeException exception) {
                removeTicketBoundChallenge(challengedPlayers, playerId, ticket);
                // Keep configurationStartAttempts: a duplicate event after a failed send must
                // remain inert. The ticket is retired by an exact disconnect or replacement.
                AuthenticatedPhysicalSession binding = authenticatedPhysicalSessions.get(playerId);
                if (binding != null && binding.playerIdentity() == player && binding.loginTicket().equals(ticket)) {
                    authenticatedPhysicalSessions.remove(playerId);
                }
                departingSession = removeBridgeSessionForReplacement(bridge, playerId);
                getLogger().warning("MCAce could not begin a handshake for " + player.getName()
                        + ": " + safeMessage(exception));
            }
        }
        // The bridge/session state was retired while holding the lifecycle lock; the executor is
        // intentionally cleared only after releasing it to preserve the established lock order.
        clearDepartingDispositionSession(player.getUniqueId(), departingSession);
    }

    private void expireSessions() {
        BungeeSessionBridge current = bridge;
        if (current == null) {
            return;
        }
        ShadowBackendContextRuntime contextRuntime = backendContextRuntime;
        if (contextRuntime != null) contextRuntime.expire();
        try {
            current.federationRuntime().ifPresent(runtime -> runtime.expire(256));
        } catch (RuntimeException exception) {
            getLogger().warning("MCAce federation expiry sweep failed: " + safeMessage(exception));
        }
        try {
            synchronized (connectionLifecycleLock) {
                // Use the same lifecycle-to-bridge order as replacement/disconnect. A new login
                // cannot publish a same-UUID ticket between terminal timeout observation and the
                // ticket-bound cleanup below.
                if (bridge != current) {
                    return;
                }
                for (PlayerSecuritySnapshot snapshot : current.expireTimedOut()) {
                    AuthenticatedPhysicalSession binding = authenticatedPhysicalSessions.get(snapshot.playerId());
                    ProxiedPlayer player = getProxy().getPlayer(snapshot.playerId());
                    BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
                    Optional<BungeeDeferredDispositionRoutes.LoginTicket> ticket = player == null || routes == null
                            ? Optional.empty() : routes.ticketFor(snapshot.playerId(), player);
                    if (ticket.isPresent() && isCurrentPhysicalLogin(player, ticket.orElseThrow())) {
                        // expireTimedOut() reports only terminal pre-auth handshakes. Revoke both
                        // configuration permissions for this exact current physical ticket so a
                        // late client frame or duplicate callback is inert; no PLAY fallback is
                        // permitted.
                        retireTerminalConfigurationTicket(
                                challengedPlayers, configurationStartAttempts, terminalConfigurationTickets,
                                snapshot.playerId(), ticket.orElseThrow());
                    }
                    if (binding != null && player == binding.playerIdentity() && routes != null
                            && routes.isCurrent(snapshot.playerId(), player, binding.loginTicket())
                            && current.isCurrentAuthenticatedSession(snapshot.playerId(), binding.sessionId())) {
                        // A timed-out snapshot is only forwarded while its own physical login and
                        // authenticated session still exist. A same-UUID replacement cannot cause
                        // an old snapshot to be re-signed with a new sequence.
                        logSnapshot(player, snapshot, false);
                        forwardSnapshot(player, binding.loginTicket(), binding.sessionId(), current, snapshot);
                    }
                }
            }
            for (HeartbeatTransition transition : current.pollHeartbeatTransitions()) {
                getLogger().info("MCAce heartbeat player=" + transition.playerId()
                        + " session=" + transition.sessionId()
                        + " " + transition.previous() + "->" + transition.current()
                        + " (monitor-only; admission unchanged)");
            }
            for (HeartbeatMissingTransition transition : current.pollHeartbeatMissingTransitions()) {
                applyHeartbeatMissingTransition(current, transition);
            }
        } catch (RuntimeException exception) {
            getLogger().warning("MCAce timed-session sweep failed: " + safeMessage(exception));
        }
    }

    private MCAceFederationCommand.Operations federationOperations() {
        return new MCAceFederationCommand.Operations() {
            @Override public FederationRuntimeState status() {
                return federationRuntime().map(FederationRuntime::status)
                        .orElseGet(() -> new FederationRuntimeState(
                                false, false, false, "unavailable", 0, 0, 0, 0, 0L, 1L));
            }

            @Override public List<String> peers() {
                return federationRuntime().map(runtime -> runtime.peerSummaries().stream()
                        .map(peer -> peer.networkId() + " capabilities=" + peer.capabilities())
                        .toList()).orElseGet(List::of);
            }

            @Override public FederationRuntimeStatus issue(
                    UUID playerId, String targetNetworkId, String operatorId) {
                synchronized (connectionLifecycleLock) {
                    ProxiedPlayer player = getProxy().getPlayer(playerId);
                    if (player == null || !isCurrentPhysicalLogin(player)) {
                        return FederationRuntimeStatus.NO_CURRENT_SUBJECT;
                    }
                    java.util.Optional<FederationRuntime> runtime = federationRuntime();
                    java.util.Optional<FederationSubject> subject = bridge == null
                            ? java.util.Optional.empty() : bridge.federationSubject(playerId);
                    if (runtime.isEmpty()) return FederationRuntimeStatus.DISABLED;
                    if (subject.isEmpty()) return FederationRuntimeStatus.NO_CURRENT_SUBJECT;
                    FederationIssueResult issued = runtime.orElseThrow().issueConsent(
                            subject.orElseThrow(), targetNetworkId, operatorId);
                    if (issued.outboundFrame().isEmpty()) return issued.status();
                    try {
                        player.sendData(BungeeMCAceChannels.HANDSHAKE, issued.outboundFrame().orElseThrow());
                        return issued.status();
                    } catch (RuntimeException exception) {
                        runtime.orElseThrow().cancelPending(playerId, subject.orElseThrow().authenticatedSessionId());
                        return FederationRuntimeStatus.INVALID_FRAME;
                    }
                }
            }
        };
    }

    private void receiveFederation(
            ProxiedPlayer player, byte[] frame, BungeeFederationInboundGate.Decision decision) {
        synchronized (connectionLifecycleLock) {
            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
            Optional<BungeeDeferredDispositionRoutes.LoginTicket> ticket = routes == null
                    ? Optional.empty() : routes.ticketFor(player.getUniqueId(), player);
            if (ticket.isEmpty() || !mayProcessConfigurationBoundFrame(
                    isCurrentPhysicalLogin(player, ticket.orElseThrow()), challengedPlayers,
                    player.getUniqueId(), ticket.orElseThrow())
                    || decision == BungeeFederationInboundGate.Decision.DROP_SERVER_ONLY) {
                return;
            }
            java.util.Optional<FederationRuntime> runtime = federationRuntime();
            java.util.Optional<FederationSubject> subject = bridge == null
                    ? java.util.Optional.empty() : bridge.federationSubject(player.getUniqueId());
            if (runtime.isEmpty() || subject.isEmpty()) {
                getLogger().info("MCAce federation frame ignored for " + player.getName()
                        + ": no current local VERIFIED session");
                return;
            }
            try {
                if (decision == BungeeFederationInboundGate.Decision.CONSENT_RESPONSE) {
                    FederationGrantResult result = runtime.orElseThrow().receiveConsentResponse(
                            subject.orElseThrow(), frame);
                    if (result.outboundFrame().isPresent()) {
                        player.sendData(BungeeMCAceChannels.HANDSHAKE, result.outboundFrame().orElseThrow());
                    }
                    getLogger().info("MCAce federation consent response status=" + result.status()
                            + " player=" + player.getUniqueId());
                    return;
                }
                if (decision == BungeeFederationInboundGate.Decision.PRESENTATION) {
                    FederationPresentationResult result = runtime.orElseThrow().receivePresentation(
                            subject.orElseThrow(), frame, "bungee-client:" + player.getUniqueId());
                    getLogger().info("MCAce federation presentation status=" + result.status()
                            + " player=" + player.getUniqueId() + " (observation-only)");
                }
            } catch (RuntimeException exception) {
                getLogger().warning("MCAce rejected a federation frame from " + player.getName()
                        + ": " + safeMessage(exception));
            }
        }
    }

    private java.util.Optional<FederationRuntime> federationRuntime() {
        BungeeSessionBridge current = bridge;
        return current == null ? java.util.Optional.empty() : current.federationRuntime();
    }

    /**
     * Removes the predecessor's exact federation session before dropping its bridge state.
     * Callers hold {@link #connectionLifecycleLock}; a new same-UUID login cannot be published
     * between these two operations.
     */
    static BungeeDeferredDispositionRoutes.LoginTicket replacePhysicalLogin(
            BungeeDeferredDispositionRoutes routes,
            Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges,
            BungeeSessionBridge current,
            UUID playerId,
            Object playerIdentity) {
        Objects.requireNonNull(routes, "routes");
        Objects.requireNonNull(challenges, "challenges");
        removeBridgeSessionForReplacement(current, playerId);
        replaceTicketBoundChallenge(challenges, playerId);
        return routes.beginLogin(playerId, playerIdentity);
    }

    /**
     * Retires the exact coordinator session before the caller may publish a same-UUID login.
     * The returned identifier is used outside the lifecycle lock to remove only that executor
     * session; it must never be widened to a UUID-only executor clear.
     */
    static Optional<String> removeBridgeSessionForReplacement(BungeeSessionBridge current, UUID playerId) {
        if (current == null) {
            return Optional.empty();
        }
        Optional<String> authenticatedSession = current.currentAuthenticatedSessionId(playerId);
        Optional<String> federationSession = current.federationSubject(playerId)
                .map(com.ellan.mcace.core.federation.FederationSubject::authenticatedSessionId);
        removeFederationSessionThenBridge(federationSession, sessionId -> current.federationRuntime()
                .ifPresent(runtime -> runtime.removeForSession(playerId, sessionId)), () -> current.remove(playerId));
        return authenticatedSession.or(() -> federationSession);
    }

    /** Separated for deterministic ordering tests: federation revocation always precedes removal. */
    static void removeFederationSessionThenBridge(
            Optional<String> federationSession,
            java.util.function.Consumer<String> removeFederationSession,
            Runnable removeBridgeSession) {
        Objects.requireNonNull(federationSession, "federationSession");
        Objects.requireNonNull(removeFederationSession, "removeFederationSession");
        Objects.requireNonNull(removeBridgeSession, "removeBridgeSession");
        federationSession.ifPresent(removeFederationSession);
        removeBridgeSession.run();
    }

    /**
     * Lock order: lifecycle state is retired first, then this method takes the executor monitor.
     * The executor itself can call back into the lifecycle lock, so no lifecycle-to-executor edge
     * may exist while the lifecycle lock is held.
     */
    private void clearDepartingDispositionSession(UUID playerId, Optional<String> departingSession) {
        BungeeDispositionExecutor executor = dispositionExecutor;
        if (executor != null) {
            departingSession.ifPresent(sessionId -> executor.clear(playerId, sessionId));
        }
    }

    /** A physical login and its authenticated protocol session, compared by player identity. */
    private record AuthenticatedPhysicalSession(
            Object playerIdentity,
            BungeeDeferredDispositionRoutes.LoginTicket loginTicket,
            String sessionId) {
        private AuthenticatedPhysicalSession {
            Objects.requireNonNull(playerIdentity, "playerIdentity");
            Objects.requireNonNull(loginTicket, "loginTicket");
            Objects.requireNonNull(sessionId, "sessionId");
        }
    }

    /** Call only under {@link #connectionLifecycleLock}. */
    private boolean isCurrentAuthenticatedPhysicalSession(
            ProxiedPlayer player,
            BungeeDeferredDispositionRoutes.LoginTicket ticket,
            BungeeSessionBridge current,
            String sessionId) {
        if (!isCurrentPhysicalLogin(player, ticket)
                || !current.isCurrentAuthenticatedSession(player.getUniqueId(), sessionId)) {
            return false;
        }
        AuthenticatedPhysicalSession binding = authenticatedPhysicalSessions.get(player.getUniqueId());
        return binding == null || (binding.playerIdentity() == player
                && binding.loginTicket().equals(ticket) && binding.sessionId().equals(sessionId));
    }

    /** Call only under {@link #connectionLifecycleLock} after {@link #isCurrentAuthenticatedPhysicalSession}. */
    private void bindAuthenticatedPhysicalSession(
            ProxiedPlayer player, BungeeDeferredDispositionRoutes.LoginTicket ticket, String sessionId) {
        authenticatedPhysicalSessions.put(player.getUniqueId(),
                new AuthenticatedPhysicalSession(player, ticket, sessionId));
    }

    /**
     * Sends a bridge action before releasing the lifecycle lock. The outbound handshake frames and
     * any signed snapshot therefore share one exact player identity/ticket/session ordering.
     */
    private void dispatchBridgeAction(
            ProxiedPlayer player,
            BungeeDeferredDispositionRoutes.LoginTicket ticket,
            BungeeSessionBridge current,
            BungeeBridgeAction action) {
        if (!isCurrentPhysicalLogin(player, ticket)) {
            return;
        }
        for (byte[] frame : action.outboundFrames()) {
            if (!isCurrentPhysicalLogin(player, ticket)) {
                return;
            }
            player.sendData(BungeeMCAceChannels.HANDSHAKE, frame);
        }
        action.snapshot().ifPresent(snapshot -> current.currentAuthenticatedSessionId(player.getUniqueId())
                .filter(sessionId -> isCurrentAuthenticatedPhysicalSession(player, ticket, current, sessionId))
                .ifPresent(sessionId -> {
                    bindAuthenticatedPhysicalSession(player, ticket, sessionId);
                    logSnapshot(player, snapshot, action.protocolViolation());
                    forwardSnapshot(player, ticket, sessionId, current, snapshot);
                }));
        if (action.protocolViolation() && action.snapshot().isEmpty()) {
            getLogger().warning("MCAce rejected a heartbeat from " + player.getName()
                    + " (monitor-only; admission unchanged)");
        }
    }

    private void applyHeartbeatMissingTransition(BungeeSessionBridge current, HeartbeatMissingTransition transition) {
        synchronized (connectionLifecycleLock) {
            ProxiedPlayer player = getProxy().getPlayer(transition.playerId());
            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
            if (player == null || routes == null
                    || routes.ticketFor(transition.playerId(), player).isEmpty()
                    || !current.isCurrentAuthenticatedSession(transition.playerId(), transition.sessionId())) return;
            BungeeDeferredDispositionRoutes.LoginTicket ticket =
                    routes.ticketFor(transition.playerId(), player).orElseThrow();
            if (transition.kind() == HeartbeatMissingTransition.Kind.RECOVER) {
                routes.clearHeartbeat(transition.playerId(), transition.sessionId(), player, ticket);
                player.sendMessage(new TextComponent("MCAce: heartbeat recovered; temporary session control cleared."));
                getLogger().info("MCAce heartbeat temporary control recovered player=" + transition.playerId()
                        + " action=" + transition.action() + " (no forced return route)");
                return;
            }
            if (transition.action() == HeartbeatMissingPolicy.Action.NOTICE) {
                player.sendMessage(new TextComponent("MCAce: heartbeat missing; this verified session is being monitored."));
                getLogger().info("MCAce heartbeat missing notice player=" + transition.playerId()
                        + " polls=" + transition.missingPolls());
                return;
            }
            Optional<BungeeDispositionRouteTargets> routeTargets = dispositionRouteTargets;
            if (current.dispositionExecutionMode() == BungeeDispositionExecutionMode.LIMITED_ROUTE
                    && routeTargets.isPresent()) {
                BungeeDispositionExecutor.Actions.RouteOutcome outcome = routeHeartbeatLimited(
                        player, transition.sessionId(), routeTargets.orElseThrow().limitedServer());
                getLogger().info("MCAce heartbeat missing temporary route player=" + transition.playerId()
                        + " polls=" + transition.missingPolls() + " result=" + outcome);
            } else {
                getLogger().info("MCAce heartbeat missing route configured but global LIMITED_ROUTE is disabled; player="
                        + transition.playerId() + " monitor-only");
            }
        }
    }

    private void refreshBackendSnapshots() {
        BungeeSessionBridge current = bridge;
        if (current == null) {
            return;
        }
        for (ProxiedPlayer player : getProxy().getPlayers()) {
            synchronized (connectionLifecycleLock) {
                BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
                Optional<BungeeDeferredDispositionRoutes.LoginTicket> ticket = routes == null
                        ? Optional.empty() : routes.ticketFor(player.getUniqueId(), player);
                if (ticket.isEmpty() || !isCurrentPhysicalLogin(player, ticket.orElseThrow())) {
                    continue;
                }
                current.currentAuthenticatedSessionId(player.getUniqueId()).ifPresent(sessionId ->
                        current.api().snapshot(player.getUniqueId()).ifPresent(snapshot -> {
                            if (isCurrentAuthenticatedPhysicalSession(player, ticket.orElseThrow(), current, sessionId)) {
                                bindAuthenticatedPhysicalSession(player, ticket.orElseThrow(), sessionId);
                                forwardSnapshot(player, ticket.orElseThrow(), sessionId, current, snapshot);
                            }
                        }));
            }
        }
    }

    private void refreshDispositionPolicy() {
        BungeeSessionBridge current = bridge;
        if (current == null) {
            return;
        }
        current.dispositionPolicyRuntime().ifPresent(this::refreshDispositionPolicy);
    }

    private void refreshDispositionPolicy(SharedProxyDispositionPolicyRuntime runtime) {
        ProxyPolicyRefreshStatus refreshStatus = runtime.refresh();
        BungeeDispositionStatus next = new BungeeDispositionStatus(refreshStatus, runtime.activeSequence());
        AtomicReference<BungeeDispositionStatus> holder = dispositionStatus;
        if (holder != null) {
            BungeeDispositionStatus previous = holder.getAndSet(next);
            if (!next.equals(previous)) {
                getLogger().info(BungeeStatusRenderer.disposition(next));
            }
        }
    }

    private java.util.Optional<BungeeDispositionPolicyPublisher> dispositionPublisher() {
        BungeeSessionBridge current = bridge;
        if (current == null) {
            return java.util.Optional.empty();
        }
        return current.dispositionPolicyPublisher().map(publisher -> () -> {
            BungeePublishedDispositionPolicy published = publisher.publish();
            refreshDispositionPolicy();
            return published;
        });
    }

    /**
     * Starts a high-impact route only after Bungee reports a successful backend connection.
     * Before that point the request is retained once, bound to this exact authenticated session.
     */
    private BungeeDispositionExecutor.Actions.RouteOutcome routeDisposition(
            UUID playerId, String sessionId, String serverName,
            com.ellan.mcace.core.disposition.DispositionAction action,
            java.util.Optional<com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent> dispositionEvent) {
        synchronized (connectionLifecycleLock) {
            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
            BungeeSessionBridge current = bridge;
            ProxiedPlayer player = getProxy().getPlayer(playerId);
            Optional<BungeeDeferredDispositionRoutes.LoginTicket> ticket = player == null || routes == null
                    ? Optional.empty() : routes.ticketFor(playerId, player);
            if ((action != com.ellan.mcace.core.disposition.DispositionAction.LIMIT
                    && action != com.ellan.mcace.core.disposition.DispositionAction.QUARANTINE)
                    || current == null || player == null || ticket.isEmpty()
                    || !current.isCurrentAuthenticatedSession(playerId, sessionId)
                    || !current.api().snapshot(playerId).map(PlayerSecuritySnapshot::verified).orElse(false)
                    || !routes.permitRoute(playerId, sessionId, player, ticket.orElseThrow())) {
                return BungeeDispositionExecutor.Actions.RouteOutcome.UNAVAILABLE;
            }
            BungeeDeferredDispositionRoutes.LoginTicket loginTicket = ticket.orElseThrow();
            if (!routes.isReady(playerId, player, loginTicket)) {
                BungeeDeferredDispositionRoutes.DeferResult deferred = dispositionEvent.isPresent()
                        ? routes.deferDisposition(dispositionEvent.orElseThrow(), serverName, loginTicket, player)
                        : routes.deferHeartbeat(playerId, sessionId, serverName, loginTicket, player);
                return switch (deferred) {
                    case QUEUED, SUPERSEDED, ALREADY_STRONGER -> BungeeDispositionExecutor.Actions.RouteOutcome.DEFERRED;
                    case CAPACITY_REJECTED, TERMINAL_REJECTED, STALE_SESSION_REJECTED ->
                            BungeeDispositionExecutor.Actions.RouteOutcome.UNAVAILABLE;
                };
            }
            net.md_5.bungee.api.config.ServerInfo target = getProxy().getServerInfo(serverName);
            if (target == null || player.getServer() == null) {
                return BungeeDispositionExecutor.Actions.RouteOutcome.UNAVAILABLE;
            }
            connectOnceWithAudit(player, loginTicket, sessionId, target, action, "direct",
                    dispositionEvent.flatMap(
                            com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent::authorizationId));
            return BungeeDispositionExecutor.Actions.RouteOutcome.DISPATCHED;
        }
    }

    private BungeeDispositionExecutor.Actions.RouteOutcome routeHeartbeatLimited(
            ProxiedPlayer player, String sessionId, String serverName) {
        return routeDisposition(player.getUniqueId(), sessionId, serverName,
                com.ellan.mcace.core.disposition.DispositionAction.LIMIT, java.util.Optional.empty());
    }

    /** Revalidates every async boundary; a claimed pending route never retries again. */
    private void retryDeferredDispositionRoute(
            ProxiedPlayer player, BungeeDeferredDispositionRoutes.LoginTicket loginTicket) {
        synchronized (connectionLifecycleLock) {
            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
            BungeeSessionBridge current = bridge;
            UUID playerId = player.getUniqueId();
            if (routes == null || current == null || !isCurrentPhysicalLogin(player, loginTicket)) return;
            Optional<BungeeDeferredDispositionRoutes.Pending> claimed =
                    routes.claimForReadyBackend(playerId, player, loginTicket);
            if (claimed.isEmpty()) return;
            BungeeDeferredDispositionRoutes.Pending pending = claimed.orElseThrow();
            if (!current.isCurrentAuthenticatedSession(playerId, pending.sessionId())
                    || !current.api().snapshot(playerId).map(PlayerSecuritySnapshot::verified).orElse(false)
                    || !routes.permitRoute(playerId, pending.sessionId(), player, loginTicket)) {
                getLogger().info("MCAce deferred disposition route result=UNAVAILABLE player=" + playerId
                        + " reason=session-or-admission");
                return;
            }
            Optional<BungeeDispositionRouteTargets> targets = dispositionRouteTargets;
            String expectedTarget = targets.flatMap(target -> switch (pending.action()) {
                case LIMIT -> Optional.of(target.limitedServer());
                case QUARANTINE -> Optional.of(target.quarantineServer());
                default -> Optional.empty();
            }).orElse(null);
            if (effectiveDispositionMode != BungeeDispositionExecutionMode.LIMITED_ROUTE
                    || expectedTarget == null || !expectedTarget.equals(pending.targetName())) {
                getLogger().info("MCAce deferred disposition route result=UNAVAILABLE player=" + playerId
                        + " reason=inactive-route");
                return;
            }
            net.md_5.bungee.api.config.ServerInfo target = getProxy().getServerInfo(expectedTarget);
            if (target == null || player.getServer() == null || !routes.isReady(playerId, player, loginTicket)) {
                getLogger().info("MCAce deferred disposition route result=UNAVAILABLE player=" + playerId
                        + " reason=backend-not-ready");
                return;
            }
            java.util.function.Supplier<Boolean> startRoute = () -> {
                connectOnceWithAudit(player, loginTicket, pending.sessionId(), target, pending.action(),
                        "deferred-" + pending.source().name().toLowerCase(java.util.Locale.ROOT),
                        pending.dispositionEvent().flatMap(
                                com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent::authorizationId));
                return true;
            };
            boolean dispatched = pending.source() == BungeeDeferredDispositionRoutes.Source.DISPOSITION
                    ? pending.dispositionEvent()
                            .flatMap(event -> executeWithCurrentDispositionPolicy(
                                    current, event, startRoute))
                            .orElse(false)
                    : startRoute.get();
            if (!dispatched) {
                getLogger().info("MCAce deferred disposition route result=UNAVAILABLE player=" + playerId
                        + " reason=inactive-policy");
                return;
            }
            getLogger().info("MCAce deferred disposition route result=DISPATCHED player=" + playerId
                    + " action=" + pending.action() + " source=" + pending.source()
                    + " authorization=" + pending.dispositionEvent()
                            .flatMap(com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent::authorizationId)
                            .map(Object::toString).orElse("none")
                    + " session-bound=true execution-context-bound="
                    + pending.dispositionEvent()
                            .flatMap(com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent::authorizationContextCommitmentSha256)
                            .isPresent());
        }
    }

    /**
     * Issues one Bungee route request and records the API's actual completion callback. This never
     * retries: the deferred entry was already claimed before this call, and a failed callback is
     * an auditable terminal result for that one request.
     */
    private void connectOnceWithAudit(
            ProxiedPlayer player,
            BungeeDeferredDispositionRoutes.LoginTicket loginTicket,
            String sessionId,
            net.md_5.bungee.api.config.ServerInfo target,
            com.ellan.mcace.core.disposition.DispositionAction action,
            String source,
            Optional<UUID> authorizationId) {
        UUID playerId = player.getUniqueId();
        AtomicBoolean completionReported = new AtomicBoolean();
        player.connect(target, (success, error) -> {
            if (!consumeRouteCompletion(completionReported)) {
                return;
            }
            synchronized (connectionLifecycleLock) {
                BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
                BungeeSessionBridge current = bridge;
                if (routes == null || current == null || !isCurrentPhysicalLogin(player, loginTicket)
                        || !current.isCurrentAuthenticatedSession(playerId, sessionId)) {
                    return; // A late callback cannot update or act on a replacement login.
                }
                String result = successfulRouteCompletion(success, error) ? "SUCCESS" : "FAILED";
                getLogger().info("MCAce disposition route completion=" + result + " player=" + playerId
                        + " action=" + action + " source=" + source + " authorization="
                        + authorizationId.map(Object::toString).orElse("none")
                        + " session-bound=true execution-context-bound=" + authorizationId.isPresent());
            }
        });
    }

    private boolean isCurrentPhysicalLogin(ProxiedPlayer player) {
        Objects.requireNonNull(player, "player");
        BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
        return routes != null && getProxy().getPlayer(player.getUniqueId()) == player
                && routes.ticketFor(player.getUniqueId(), player).isPresent();
    }

    private boolean isCurrentPhysicalLogin(
            ProxiedPlayer player, BungeeDeferredDispositionRoutes.LoginTicket loginTicket) {
        Objects.requireNonNull(player, "player");
        Objects.requireNonNull(loginTicket, "loginTicket");
        BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
        return routes != null && getProxy().getPlayer(player.getUniqueId()) == player
                && routes.isCurrent(player.getUniqueId(), player, loginTicket);
    }

    static boolean installTicketBoundChallenge(
            Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges,
            UUID playerId,
            BungeeDeferredDispositionRoutes.LoginTicket ticket) {
        return Objects.requireNonNull(challenges, "challenges")
                .putIfAbsent(Objects.requireNonNull(playerId, "playerId"),
                        Objects.requireNonNull(ticket, "ticket")) == null;
    }

    /** True only while the supplied ticket is the exact configuration-armed challenge. */
    static boolean isTicketBoundChallenge(
            Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges,
            UUID playerId,
            BungeeDeferredDispositionRoutes.LoginTicket ticket) {
        return Objects.requireNonNull(ticket, "ticket").equals(Objects.requireNonNull(challenges, "challenges")
                .get(Objects.requireNonNull(playerId, "playerId")));
    }

    /** Both the live Bungee identity gate and the exact configuration challenge are required. */
    static boolean mayProcessConfigurationBoundFrame(
            boolean currentPhysicalLogin,
            Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges,
            UUID playerId,
            BungeeDeferredDispositionRoutes.LoginTicket ticket) {
        return currentPhysicalLogin && isTicketBoundChallenge(challenges, playerId, ticket);
    }

    /** Retires both configuration markers only when they still belong to this exact ticket. */
    static boolean retireTerminalConfigurationTicket(
            Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges,
            Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> attempts,
            Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> terminalTickets,
            UUID playerId,
            BungeeDeferredDispositionRoutes.LoginTicket ticket) {
        boolean challengeRemoved = removeTicketBoundChallenge(challenges, playerId, ticket);
        boolean attemptRemoved = removeTicketBoundChallenge(attempts, playerId, ticket);
        if (challengeRemoved || attemptRemoved) {
            Objects.requireNonNull(terminalTickets, "terminal tickets").putIfAbsent(playerId, ticket);
            return true;
        }
        return false;
    }

    /**
     * A begin() without hello must not authorize inbound frames. The attempt marker is intentionally
     * not accepted here, so duplicate configuration callbacks remain one-shot/inert.
     */
    static Optional<String> retireUnsentConfigurationHandshake(
            Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges,
            BungeeSessionBridge current,
            UUID playerId,
            BungeeDeferredDispositionRoutes.LoginTicket ticket) {
        removeTicketBoundChallenge(challenges, playerId, ticket);
        return removeBridgeSessionForReplacement(current, playerId);
    }

    /**
     * Decides whether this exact ticket may make its one initial configuration-phase begin()
     * attempt. A previous failed attempt is terminal until its physical login is retired.
     */
    static boolean mayStartConfigurationHandshake(
            Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges,
            Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> attempts,
            Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> terminalTickets,
            UUID playerId,
            BungeeDeferredDispositionRoutes.LoginTicket ticket) {
        Objects.requireNonNull(challenges, "challenges");
        Objects.requireNonNull(attempts, "attempts");
        Objects.requireNonNull(terminalTickets, "terminal tickets");
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(ticket, "ticket");
        return !challenges.containsKey(playerId) && !attempts.containsKey(playerId)
                && !terminalTickets.containsKey(playerId);
    }

    /** Compatibility helper for tests and third-party callers without a terminal-timeout map. */
    static boolean mayStartConfigurationHandshake(
            Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges,
            Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> attempts,
            UUID playerId,
            BungeeDeferredDispositionRoutes.LoginTicket ticket) {
        return mayStartConfigurationHandshake(challenges, attempts, Map.of(), playerId, ticket);
    }

    /** LOGIN is the only Bungee configuration reason allowed to start the initial handshake. */
    static boolean isInitialConfigurationReason(PlayerConfigurationEvent.Reason reason) {
        return reason == PlayerConfigurationEvent.Reason.LOGIN;
    }

    static boolean removeTicketBoundChallenge(
            Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges,
            UUID playerId,
            BungeeDeferredDispositionRoutes.LoginTicket ticket) {
        return Objects.requireNonNull(challenges, "challenges").remove(
                Objects.requireNonNull(playerId, "playerId"), Objects.requireNonNull(ticket, "ticket"));
    }

    static void replaceTicketBoundChallenge(
            Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges, UUID playerId) {
        Objects.requireNonNull(challenges, "challenges").remove(Objects.requireNonNull(playerId, "playerId"));
    }

    static boolean consumeRouteCompletion(AtomicBoolean completionReported) {
        return Objects.requireNonNull(completionReported, "completionReported").compareAndSet(false, true);
    }

    /** Bungee may report false, null, or an error; only an explicit true without an error succeeds. */
    static boolean successfulRouteCompletion(Boolean success, Throwable error) {
        return Boolean.TRUE.equals(success) && error == null;
    }

    private BungeeSessionBridge discoverBridge(Path dataDirectory) {
        List<BungeeSessionBridgeFactory> factories = ServiceLoader.load(
                        BungeeSessionBridgeFactory.class, getClass().getClassLoader())
                .stream()
                .map(ServiceLoader.Provider::get)
                .toList();
        if (factories.isEmpty()) {
            getLogger().warning("No MCAce Bungee session bridge provider found; adapter is status-only");
            return new DisabledBungeeSessionBridge();
        }
        if (factories.size() != 1) {
            getLogger().severe("Expected exactly one MCAce Bungee session bridge provider; adapter is status-only");
            return new DisabledBungeeSessionBridge();
        }
        try {
            return Objects.requireNonNull(
                    factories.getFirst().create(dataDirectory, getLogger()), "bridge factory result");
        } catch (Exception exception) {
            getLogger().severe("MCAce Bungee bridge provider failed; adapter is status-only: "
                    + safeMessage(exception));
            return new DisabledBungeeSessionBridge();
        }
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
        ProxiedPlayer player = getProxy().getPlayer(playerName);
        if (player == null) {
            return MCAceDispositionReviewCommand.ReviewResult.status(
                    MCAceDispositionReviewCommand.Status.UNKNOWN_PLAYER);
        }
        String sessionId;
        String backendId;
        synchronized (connectionLifecycleLock) {
            BungeeSessionBridge current = bridge;
            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
            Optional<BungeeDeferredDispositionRoutes.LoginTicket> ticket = current == null || routes == null
                    ? Optional.empty() : routes.ticketFor(player.getUniqueId(), player);
            Optional<String> session = current == null
                    ? Optional.empty() : current.currentAuthenticatedSessionId(player.getUniqueId());
            boolean verified = current != null && current.api().snapshot(player.getUniqueId())
                    .map(snapshot -> snapshot.verified()
                            && snapshot.admissionStatus() == AdmissionStatus.VERIFIED)
                    .orElse(false);
            if (current == null || ticket.isEmpty() || session.isEmpty() || !verified
                    || !isCurrentAuthenticatedPhysicalSession(
                    player, ticket.orElseThrow(), current, session.orElseThrow())) {
                return MCAceDispositionReviewCommand.ReviewResult.status(
                        MCAceDispositionReviewCommand.Status.NO_CURRENT_AUTHENTICATED_SESSION);
            }
            sessionId = session.orElseThrow();
            backendId = player.getServer() == null ? null : player.getServer().getInfo().getName();
        }
        com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent event;
        try {
            event = authorizations.authorizeAdministratorReview(
                    player.getUniqueId(), sessionId,
                    new EvaluationContext(
                            player.getUniqueId(), "bungeecord", backendId, null, null, Set.of(), clock.instant()),
                    request.observation(), operatorId, request.reviewTicket());
            getLogger().info("MCAce trusted disposition authorization persisted: authorization="
                    + event.authorizationId().orElseThrow()
                    + " journal-durable=true execution-context-bound=true player="
                    + event.playerId() + " action=" + event.highestAction() + " policy-sequence="
                    + event.activePolicySequence().orElseThrow());
        } catch (java.io.IOException | RuntimeException exception) {
            getLogger().warning("MCAce administrator-reviewed disposition authorization failed closed: "
                    + exception.getClass().getSimpleName());
            return MCAceDispositionReviewCommand.ReviewResult.status(
                    MCAceDispositionReviewCommand.Status.FAILED);
        }
        BungeeDispositionExecutor executor = dispositionExecutor;
        if (executor == null || !executor.offer(event)) {
            getLogger().warning("MCAce administrator-reviewed disposition execution queue is unavailable");
            return MCAceDispositionReviewCommand.ReviewResult.status(
                    MCAceDispositionReviewCommand.Status.EXECUTION_QUEUE_UNAVAILABLE);
        }
        return new MCAceDispositionReviewCommand.ReviewResult(
                MCAceDispositionReviewCommand.Status.AUTHORIZED,
                Optional.of(event.highestAction()), event.winningRuleId(),
                event.activePolicySequence(), event.authorizationId());
    }
    private BungeeDispositionExecutor createDispositionExecutor(BungeeSessionBridge current) {
        Optional<BungeeDispositionRouteTargets> resolvedTargets = resolveDispositionRouteTargets(
                current.dispositionExecutionMode(), current.dispositionLimitedServer(),
                current.dispositionQuarantineServer(), getProxy().getServers().keySet());
        dispositionRouteTargets = resolvedTargets;
        BungeeDispositionExecutionMode effectiveMode = effectiveDispositionExecutionMode(
                current.dispositionExecutionMode(), resolvedTargets);
        effectiveDispositionMode = effectiveMode;
        if (current.dispositionExecutionMode() == BungeeDispositionExecutionMode.LIMITED_ROUTE
                && resolvedTargets.isEmpty()) {
            BungeeDispositionRouteTargets.ValidationStatus status =
                    BungeeDispositionRouteTargets.validationStatus(
                            current.dispositionExecutionMode(), current.dispositionLimitedServer(),
                            current.dispositionQuarantineServer(), getProxy().getServers().keySet());
            getLogger().warning("MCAce high-impact disposition routing disabled: status=" + status);
        }
        return new BungeeDispositionExecutor(
                effectiveMode,
                resolvedTargets.orElseGet(() -> new BungeeDispositionRouteTargets("disabled-limit", "disabled-quarantine")),
                64,
                task -> getProxy().getScheduler().schedule(this, task, 0, TimeUnit.MILLISECONDS),
                new BungeeDispositionExecutor.Actions() {
                    @Override
                    public boolean isCurrentAuthenticatedSession(UUID playerId, String sessionId) {
                        return current.isCurrentAuthenticatedSession(playerId, sessionId);
                    }

                    @Override
                    public boolean isVerifiedAdmission(UUID playerId) {
                        return current.api().snapshot(playerId)
                                .map(snapshot -> snapshot.verified()
                                        && snapshot.admissionStatus() == AdmissionStatus.VERIFIED)
                                .orElse(false);
                    }

                    @Override
                    public boolean isCurrentAuthorizationContext(
                            com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent event) {
                        synchronized (connectionLifecycleLock) {
                            return currentAuthorizationContextMatchesLocked(current, event);
                        }
                    }

                    @Override
                    public boolean sendMessage(UUID playerId, String sessionId, String message) {
                        synchronized (connectionLifecycleLock) {
                            ProxiedPlayer player = getProxy().getPlayer(playerId);
                            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
                            Optional<BungeeDeferredDispositionRoutes.LoginTicket> ticket = player == null || routes == null
                                    ? Optional.empty() : routes.ticketFor(playerId, player);
                            if (player == null || ticket.isEmpty()
                                    || !isCurrentAuthenticatedPhysicalSession(
                                            player, ticket.orElseThrow(), current, sessionId)) {
                                return false;
                            }
                            player.sendMessage(new TextComponent(message));
                            return true;
                        }
                    }

                    @Override
                    public BungeeDispositionExecutor.Actions.RouteOutcome routeToServer(
                            com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent event, String server) {
                        synchronized (connectionLifecycleLock) {
                            return executeWithCurrentDispositionPolicy(current, event, () ->
                                    routeDisposition(event.playerId(), event.sessionId(), server,
                                            event.highestAction(), Optional.of(event)))
                                    .orElse(BungeeDispositionExecutor.Actions.RouteOutcome.UNAVAILABLE);
                        }
                    }

                    @Override
                    public boolean deny(UUID playerId, String sessionId, String message) {
                        synchronized (connectionLifecycleLock) {
                            ProxiedPlayer player = getProxy().getPlayer(playerId);
                            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
                            Optional<BungeeDeferredDispositionRoutes.LoginTicket> ticket = player == null || routes == null
                                    ? Optional.empty() : routes.ticketFor(playerId, player);
                            if (player == null || routes == null || ticket.isEmpty()
                                    || !current.isCurrentAuthenticatedSession(playerId, sessionId)
                                    || !routes.markDenied(playerId, sessionId, player, ticket.orElseThrow())) {
                                return false;
                            }
                            player.disconnect(new TextComponent(message));
                            return true;
                        }
                    }

                    @Override
                    public boolean deny(
                            com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent event,
                            String message) {
                        synchronized (connectionLifecycleLock) {
                            return executeWithCurrentDispositionPolicy(
                                    current, event,
                                    () -> deny(event.playerId(), event.sessionId(), message))
                                    .orElse(false);
                        }
                    }
                },
                activeClock(),
                event -> isCurrentDispositionPolicy(current, event),
                (event, result) -> {
                    if (result.status() != BungeeDispositionExecutor.Status.OBSERVE) {
                        getLogger().info("MCAce manifest disposition: action=" + result.action()
                                + " result=" + result.status() + " player=" + event.playerId()
                                + " authorization=" + event.authorizationId().map(Object::toString).orElse("none")
                                + " session-bound=true execution-context-bound="
                                + event.authorizationContextCommitmentSha256().isPresent());
                    }
                });
    }

    private static boolean isCurrentDispositionPolicy(
            BungeeSessionBridge current,
            com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent event) {
        if (event.activePolicyVersion().isEmpty()
                || event.activePolicySequence().isEmpty()
                || event.activePolicyExpiresAt().isEmpty()
                || event.winningRuleId().isEmpty()) {
            return false;
        }
        return current.dispositionPolicyRuntime()
                .map(runtime -> runtime.isCurrentActivePolicy(
                        event.activePolicyVersion().orElseThrow(),
                        event.activePolicySequence().orElseThrow(),
                        event.activePolicyExpiresAt().orElseThrow(),
                        event.winningRuleId().orElseThrow(),
                        event.highestAction()))
                .orElse(false);
    }

    private <T> Optional<T> executeWithCurrentDispositionPolicy(
            BungeeSessionBridge current,
            com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent event,
            java.util.function.Supplier<T> operation) {
        if (event.activePolicyVersion().isEmpty()
                || event.activePolicySequence().isEmpty()
                || event.activePolicyExpiresAt().isEmpty()
                || event.winningRuleId().isEmpty()) {
            return Optional.empty();
        }
        if (!Thread.holdsLock(connectionLifecycleLock)
                || !currentAuthorizationContextMatchesLocked(current, event)) {
            return Optional.empty();
        }
        return current.dispositionPolicyRuntime()
                .flatMap(runtime -> runtime.executeIfCurrentActivePolicy(
                        event.activePolicyVersion().orElseThrow(),
                        event.activePolicySequence().orElseThrow(),
                        event.activePolicyExpiresAt().orElseThrow(),
                        event.winningRuleId().orElseThrow(), event.highestAction(), operation));
    }

    /** Call only while holding the physical-login lifecycle boundary. */
    private boolean currentAuthorizationContextMatchesLocked(
            BungeeSessionBridge current,
            com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent event) {
        if (!Thread.holdsLock(connectionLifecycleLock)
                || event.authorizationId().isEmpty()
                || event.authorizationContextCommitmentSha256().isEmpty()) {
            return false;
        }
        ProxiedPlayer player = getProxy().getPlayer(event.playerId());
        BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
        Optional<BungeeDeferredDispositionRoutes.LoginTicket> ticket = player == null || routes == null
                ? Optional.empty() : routes.ticketFor(event.playerId(), player);
        boolean verified = current.api().snapshot(event.playerId())
                .map(snapshot -> snapshot.verified()
                        && snapshot.admissionStatus() == AdmissionStatus.VERIFIED)
                .orElse(false);
        if (player == null || ticket.isEmpty() || !verified
                || !isCurrentAuthenticatedPhysicalSession(
                player, ticket.orElseThrow(), current, event.sessionId())
                || !routes.isReady(event.playerId(), player, ticket.orElseThrow())) {
            return false;
        }
        String backend = player.getServer() == null
                ? null : player.getServer().getInfo().getName();
        EvaluationContext context = new EvaluationContext(
                event.playerId(), "bungeecord", backend, null, null, Set.of(), activeClock().instant());
        return TrustedDispositionCommitments.executionContextMatches(
                event.authorizationId().orElseThrow(), context,
                event.authorizationContextCommitmentSha256().orElseThrow());
    }

    static Optional<BungeeDispositionRouteTargets> resolveDispositionRouteTargets(
            BungeeDispositionExecutionMode mode,
            Optional<String> limitedServer,
            Optional<String> quarantineServer,
            Set<String> registeredServers) {
        return BungeeDispositionRouteTargets.resolve(mode, limitedServer, quarantineServer, registeredServers);
    }

    static BungeeDispositionExecutionMode effectiveDispositionExecutionMode(
            BungeeDispositionExecutionMode configuredMode,
            Optional<BungeeDispositionRouteTargets> routeTargets) {
        Objects.requireNonNull(configuredMode, "configuredMode");
        Objects.requireNonNull(routeTargets, "routeTargets");
        return configuredMode == BungeeDispositionExecutionMode.LIMITED_ROUTE && routeTargets.isEmpty()
                ? BungeeDispositionExecutionMode.MONITOR : configuredMode;
    }

    private void logSnapshot(ProxiedPlayer player, PlayerSecuritySnapshot snapshot, boolean protocolViolation) {
        String suffix = protocolViolation ? " protocol-violation=true" : "";
        getLogger().info("MCAce state player=" + player.getName()
                + " trust=" + snapshot.trustLevel()
                + " admission=" + snapshot.admissionStatus()
                + " risk=" + snapshot.riskScore()
                + " observedAt=" + snapshot.evaluatedAt() + suffix
                + " (observational; no automatic punishment)");
    }

    /** Call only under {@link #connectionLifecycleLock}. */
    private void forwardSnapshot(
            ProxiedPlayer player,
            BungeeDeferredDispositionRoutes.LoginTicket ticket,
            String sessionId,
            BungeeSessionBridge current,
            PlayerSecuritySnapshot snapshot) {
        if (!isCurrentAuthenticatedPhysicalSession(player, ticket, current, sessionId)
                || admissionSigningKey == null || admissionSnapshotCodec == null) {
            return;
        }
        // Bungee's current-server pointer is outside MCAce's lifecycle lock. Capture one exact
        // connection so the backend id armed in the runtime and the recipient of the signed frame
        // can never come from two sides of a concurrent server switch.
        Server backend = player.getServer();
        if (backend == null) return;
        try {
            long transportSequence = nextAdmissionSequence();
            SignedAdmissionSnapshotCodec.SignedAdmissionSnapshot signed =
                    admissionSnapshotCodec.signWithExpiry(
                    snapshot, BACKEND_SNAPSHOT_TTL, transportSequence, admissionSigningKey);
            ShadowBackendContextRuntime contextRuntime = backendContextRuntime;
            if (contextRuntime != null) {
                contextRuntime.expectBackend(
                        player.getUniqueId(), sessionId, backend.getInfo().getName(),
                        transportSequence, signed.expiresAt());
            }
            backend.sendData(BungeeMCAceChannels.ADMISSION, signed.encodedFrame());
        } catch (EnvelopeException exception) {
            getLogger().warning("Could not sign MCAce backend admission snapshot for " + player.getName()
                    + ": " + safeMessage(exception));
        }
    }

    private void receiveBackendContext(PluginMessageEvent event) {
        ShadowBackendContextRuntime runtime = backendContextRuntime;
        if (runtime == null || !(event.getSender() instanceof Server backend)
                || !(event.getReceiver() instanceof ProxiedPlayer player)) {
            return;
        }
        ShadowBackendContextRuntime.ReceiveResult result;
        synchronized (connectionLifecycleLock) {
            BungeeSessionBridge current = bridge;
            BungeeDeferredDispositionRoutes routes = deferredDispositionRoutes;
            Optional<BungeeDeferredDispositionRoutes.LoginTicket> ticket = current == null || routes == null
                    ? Optional.empty() : routes.ticketFor(player.getUniqueId(), player);
            Optional<String> sessionId = current == null
                    ? Optional.empty() : current.currentAuthenticatedSessionId(player.getUniqueId());
            if (ticket.isEmpty() || sessionId.isEmpty()
                    || !isCurrentAuthenticatedPhysicalSession(
                    player, ticket.orElseThrow(), current, sessionId.orElseThrow())) {
                return;
            }
            // Bungee can deliver the backend reply before getServer() advances. The runtime's
            // authenticated session, backend id and admission sequence binding rejects stale or
            // unrelated connections without relying on that eventually-consistent pointer.
            result = runtime.receive(
                    player.getUniqueId(), backend.getInfo().getName(), event.getData());
        }
        if (result.acceptedContext().isPresent()) {
            getLogger().fine("MCAce accepted backend context for " + player.getName()
                    + " status=" + result.status() + " (shadow-only)");
        } else {
            getLogger().warning("MCAce rejected backend context for " + player.getName()
                    + " status=" + result.status() + " (admission unchanged)");
        }
    }

    private long nextAdmissionSequence() {
        return Objects.requireNonNull(admissionSequence, "admission sequence").updateAndGet(
                previous -> Math.max(Math.incrementExact(previous), Math.max(1L, activeClock().millis())));
    }

    private Clock activeClock() {
        return Objects.requireNonNull(clock, "clock");
    }

    private BungeeSessionBridge activeBridge() {
        return Objects.requireNonNull(bridge, "MCAce Bungee adapter is disabled");
    }

    private static String safeMessage(Throwable throwable) {
        String message = throwable.getMessage();
        return message == null || message.isBlank() ? throwable.getClass().getSimpleName() : message;
    }
}
