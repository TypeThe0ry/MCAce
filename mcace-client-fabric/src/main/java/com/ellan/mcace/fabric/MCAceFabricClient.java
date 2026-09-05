package com.ellan.mcace.fabric;

import com.ellan.mcace.client.integrity.ClientIntegrityBundle;
import com.ellan.mcace.client.integrity.IntegrityScanCancellation;
import com.ellan.mcace.client.integrity.IntegrityScanException;
import com.ellan.mcace.client.integrity.PolicyDrivenIntegrityCollector;
import com.ellan.mcace.client.observation.ArtifactObservationCollector;
import com.ellan.mcace.client.observation.LoadedModObservation;
import com.ellan.mcace.client.observation.ShaderPackObservation;
import com.ellan.mcace.client.policy.VerifiedPolicy;
import com.ellan.mcace.client.policy.VerifiedPolicyCache;
import com.ellan.mcace.client.federation.ConnectionEnablementAuthorization;
import com.ellan.mcace.client.session.ClientHandshakeEngine;
import com.ellan.mcace.client.federation.FederationTokenVault;
import com.ellan.mcace.client.session.ServerKeyPins;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.generated.ArtifactObservationResultReason;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import java.io.IOException;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientLifecycleEvents;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.fabricmc.fabric.api.client.rendering.v1.world.WorldRenderEvents;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.client.gui.screen.multiplayer.ConnectScreen;
import net.minecraft.client.MinecraftClient;
import net.minecraft.client.network.ClientPlayNetworkHandler;
import net.minecraft.client.network.ServerAddress;
import net.minecraft.client.network.ServerInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class MCAceFabricClient implements ClientModInitializer {
    public static final String MOD_ID = "mcace";
    private static final String EXPECTED_ARTIFACT_SHA256_PROPERTY =
            "mcace.platform-smoke.expected-artifact-sha256";
    private static final Logger LOGGER = LoggerFactory.getLogger(MOD_ID);

    private ServerKeyPins serverKeyPins;
    private Path gameDirectory;
    private FabricClientBuildMetadata buildMetadata;
    private VerifiedPolicyCache policyCache;
    private ClientHandshakeEngine handshake;
    private PendingChallenge pendingChallenge;
    private final AuthenticationAttemptGate authenticationAttempts = new AuthenticationAttemptGate();
    private final HeartbeatSendSchedule heartbeatSchedule = new HeartbeatSendSchedule(
            Clock.systemUTC(), ProtocolConstants.HEARTBEAT_INTERVAL);
    private final ArtifactObservationSendSchedule observationSchedule = new ArtifactObservationSendSchedule(
            Clock.systemUTC(), ProtocolConstants.ARTIFACT_OBSERVATION_INTERVAL);
    private final ConnectionBoundIntegrityTask authenticationIntegrityTask = new ConnectionBoundIntegrityTask();
    private final ConnectionBoundIntegrityTask observationIntegrityTask = new ConnectionBoundIntegrityTask();
    private List<String> lastReportedResourcePacks = List.of();
    private List<String> lastReportedShaderPacks = List.of();
    private List<LoadedModObservation> lastReportedLoadedMods = List.of();
    private PendingArtifactObservationUpdate pendingArtifactObservationUpdate;
    private EvidenceCaptureController evidenceCapture;
    private final FederationTokenVault federationVault = new FederationTokenVault();
    private final MCAceEnablementController mcaceEnablement = new MCAceEnablementController();
    private final ExplicitFileConsentController explicitFileConsent = new ExplicitFileConsentController();
    private volatile ConnectionEnablementAuthorization enablementAuthorization;
    private volatile ExplicitFileAuthorization explicitFileAuthorization;
    private final ArrayDeque<QueuedEvidenceFrames> evidenceFrames = new ArrayDeque<>();

    @Override
    public void onInitializeClient() {
        FabricLoader fabricLoader = FabricLoader.getInstance();
        gameDirectory = fabricLoader.getGameDir();
        buildMetadata = FabricClientBuildMetadata.load(fabricLoader);
        serverKeyPins = loadPins(gameDirectory.resolve("config").resolve("mcace").resolve("server-keys.properties"));
        policyCache = new VerifiedPolicyCache(
                gameDirectory.resolve("config").resolve("mcace").resolve("policies"), Clock.systemUTC());
        evidenceCapture = new EvidenceCaptureController(Clock.systemUTC());
        PayloadTypeRegistry.playS2C().register(MCAcePayload.ID, MCAcePayload.CODEC);
        PayloadTypeRegistry.playS2C().register(MCAceBackendContextPayload.ID, MCAceBackendContextPayload.CODEC);
        PayloadTypeRegistry.playC2S().register(MCAcePayload.ID, MCAcePayload.CODEC);
        PayloadTypeRegistry.playC2S().register(MCAceTransferPayload.ID, MCAceTransferPayload.CODEC);
        ClientPlayNetworking.registerGlobalReceiver(MCAcePayload.ID, this::receivePayload);
        ClientPlayNetworking.registerGlobalReceiver(
                MCAceBackendContextPayload.ID, this::receiveBackendContext);
        ClientTickEvents.END_CLIENT_TICK.register(client -> {
            resumePendingChallenge(client);
            mcaceEnablement.tick(client);
            scheduleHeartbeat(client);
            scheduleArtifactObservation(client);
            evidenceCapture.tick(client);
            pumpEvidenceFrames(client);
            federationVault.discardExpired(Clock.systemUTC());
        });
        ClientPlayConnectionEvents.DISCONNECT.register((handler, client) -> {
            cancelAuthentication("disconnect");
            federationVault.onConnectionClosed();
        });
        WorldRenderEvents.END_MAIN.register(
                context -> evidenceCapture.captureAtEndOfWorldRender(MinecraftClient.getInstance()));
        ClientLifecycleEvents.CLIENT_STOPPING.register(client -> {
            authenticationAttempts.cancel();
            authenticationIntegrityTask.close();
            observationIntegrityTask.close();
            pendingArtifactObservationUpdate = null;
            observationSchedule.cancel();
            mcaceEnablement.cancel(client);
            explicitFileConsent.cancel(client);
            enablementAuthorization = null;
            explicitFileAuthorization = null;
            federationVault.close();
            evidenceCapture.close();
        });
        configurePlatformSmokeConnection();
        LOGGER.info("{}", artifactLoadedMarker());
        LOGGER.info("MCAce Fabric client initialized; {} server key pin(s) available",
                serverKeyPins.empty() ? "no" : "configured");
    }

    private String artifactLoadedMarker() {
        String expectedArtifactSha256 = System.getProperty(EXPECTED_ARTIFACT_SHA256_PROPERTY, "").strip();
        if (expectedArtifactSha256.isEmpty()) {
            return buildMetadata.artifactLoadedMarker();
        }
        String actualArtifactSha256 = FabricClientBuildMetadata.verifiedCodeSourceSha256(
                MCAceFabricClient.class, expectedArtifactSha256);
        return buildMetadata.artifactLoadedMarker(actualArtifactSha256);
    }

    private void configurePlatformSmokeConnection() {
        String address = System.getProperty("mcace.platform-smoke.server-address", "").trim();
        if (address.isEmpty()) {
            return;
        }
        ClientLifecycleEvents.CLIENT_STARTED.register(client -> client.execute(() -> {
            ServerInfo server = new ServerInfo("MCAce platform smoke", address, ServerInfo.ServerType.OTHER);
            LOGGER.info("MCAce platform smoke connecting to {}", address);
            ConnectScreen.connect(
                    client.currentScreen,
                    client,
                    ServerAddress.parse(address),
                    server,
                    false,
                    null);
        }));
    }

    private void receiveBackendContext(
            MCAceBackendContextPayload payload, ClientPlayNetworking.Context context) {
        // Backend context is server-owned and must terminate at the proxy. Never parse or act on it.
        LOGGER.warn("MCAce ignored a backend-only context frame that escaped the proxy boundary");
    }

    private void receivePayload(MCAcePayload payload, ClientPlayNetworking.Context context) {
        LOGGER.info("MCAce received handshake payload bytes={}", payload.data().length);
        SignedEnvelope envelope;
        try {
            envelope = SignedEnvelope.parseFrom(payload.data());
        } catch (com.google.protobuf.InvalidProtocolBufferException exception) {
            LOGGER.warn("MCAce ignored a malformed server frame");
            return;
        }
        if (envelope.getHeader().getPacketType() == PacketType.SERVER_HELLO) {
            receiveServerHello(payload, context);
        } else if (envelope.getHeader().getPacketType() == PacketType.AUTH_RESULT) {
            receiveAuthResult(envelope, payload, context);
        } else if (envelope.getHeader().getPacketType() == PacketType.ARTIFACT_OBSERVATION_RESULT) {
            receiveArtifactObservationResult(payload);
        } else if (envelope.getHeader().getPacketType() == PacketType.EVIDENCE_REQUEST) {
            receiveEvidenceRequest(payload, context);
        } else if (envelope.getHeader().getPacketType() == PacketType.EVIDENCE_ACK) {
            receiveEvidenceAck(payload, context);
        } else if (envelope.getHeader().getPacketType() == PacketType.EVIDENCE_ERROR) {
            receiveEvidenceError(payload, context);
        } else if (envelope.getHeader().getPacketType() == PacketType.FEDERATION_CONSENT_REQUEST) {
            receiveFederationConsentRequest(payload, context);
        } else if (envelope.getHeader().getPacketType() == PacketType.FEDERATION_GRANT) {
            receiveFederationGrant(payload, context);
        } else {
            LOGGER.warn("MCAce ignored unexpected server packet type {}", envelope.getHeader().getPacketType());
        }
    }

    private void receiveServerHello(MCAcePayload payload, ClientPlayNetworking.Context context) {
        authenticationAttempts.cancel();
        authenticationIntegrityTask.cancel();
        observationIntegrityTask.cancel();
        lastReportedResourcePacks = List.of();
        lastReportedShaderPacks = List.of();
        lastReportedLoadedMods = List.of();
        pendingArtifactObservationUpdate = null;
        cancelQueuedEvidenceFrames();
        evidenceCapture.cancel(context.client());
        mcaceEnablement.cancel(context.client());
        explicitFileConsent.cancel(context.client());
        invalidateAndCancelTargetClaim(enablementAuthorization);
        enablementAuthorization = null;
        explicitFileAuthorization = null;
        long generation = authenticationAttempts.begin();
        heartbeatSchedule.cancel();
        observationSchedule.cancel();
        pendingChallenge = null;
        handshake = null;
        ServerInfo server = context.client().getCurrentServerEntry();
        String address = server == null
                ? System.getProperty("mcace.platform-smoke.server-address", "default")
                : server.address;
        Optional<PublicKey> pinnedKey = serverKeyPins.find(address);
        if (pinnedKey.isEmpty()) {
            LOGGER.warn("MCAce will not authenticate to {} because no pinned server key is configured", address);
            return;
        }
        ClientPlayNetworkHandler networkHandler = context.client().getNetworkHandler();
        if (networkHandler == null || networkHandler.getProfile() == null) {
            pendingChallenge = new PendingChallenge(payload.data(), address, pinnedKey.orElseThrow(), generation);
            LOGGER.info("MCAce deferred the signed challenge until the play network profile is available");
            return;
        }
        beginServerHello(
                payload.data(),
                address,
                pinnedKey.orElseThrow(),
                networkHandler.getProfile().id(),
                context.client(),
                generation);
    }

    private void resumePendingChallenge(MinecraftClient client) {
        PendingChallenge pending = pendingChallenge;
        if (pending == null) {
            return;
        }
        ClientPlayNetworkHandler networkHandler = client.getNetworkHandler();
        if (networkHandler == null || networkHandler.getProfile() == null) {
            return;
        }
        pendingChallenge = null;
        beginServerHello(
                pending.frame(),
                pending.address(),
                pending.pinnedKey(),
                networkHandler.getProfile().id(),
                client,
                pending.generation());
    }

    private void beginServerHello(
            byte[] frame,
            String address,
            PublicKey pinnedKey,
            java.util.UUID playerId,
            MinecraftClient client,
            long generation) {
        AtomicReference<FederationTokenVault.TargetHandshakeClaim> claimedTarget =
                new AtomicReference<>();
        AtomicReference<ClientHandshakeEngine> verifiedCandidate = new AtomicReference<>();
        Runnable schedulingRollback = () -> {
            Optional.ofNullable(claimedTarget.get()).ifPresent(federationVault::cancelTargetClaim);
            ClientHandshakeEngine candidate = verifiedCandidate.get();
            if (candidate != null) {
                cancelAuthentication(candidate, generation, "target enablement scheduling failed");
            } else if (authenticationAttempts.isActive(generation)) {
                cancelAuthentication("policy verification scheduling failed");
            }
        };
        if (!scheduleOrRollbackOnRuntimeFailure(
                () -> Thread.ofVirtual().name("mcace-policy-verification").start(() -> {
            try {
                // Never use the payload's provisional serverId to look inside the federation
                // vault. A server can send an arbitrary plugin message before SERVER_HELLO's
                // envelope signature is checked; letting that text select a target would allow
                // it to burn a player-approved grant by naming a different pinned target.
                ClientHandshakeEngine preliminary = new ClientHandshakeEngine(playerId,
                        buildMetadata.clientVersion(), buildMetadata.minecraftVersion(), buildMetadata.buildId(),
                        LoaderType.FABRIC, pinnedKey, Clock.systemUTC(), new SecureRandom());
                VerifiedPolicy policy = preliminary.prepareServerHello(frame, address, policyCache);
                Optional<FederationTokenVault.TargetHandshakeClaim> targetClaim =
                        federationVault.claimTargetHandshake(
                                preliminary.verifiedServerId(), playerId, buildMetadata.clientVersion(),
                                buildMetadata.minecraftVersion(), buildMetadata.buildId(), LoaderType.FABRIC,
                                pinnedKey, Clock.systemUTC(), new SecureRandom());
                targetClaim.ifPresent(claimedTarget::set);
                ClientHandshakeEngine candidate = targetClaim
                        .map(FederationTokenVault.TargetHandshakeClaim::engine)
                        .orElse(preliminary);
                verifiedCandidate.set(candidate);
                if (targetClaim.isPresent()) {
                    // Re-verify the same signed hello and policy with the exact, vault-owned
                    // target key. Only this engine may emit the final CLIENT_HELLO.
                    policy = candidate.prepareServerHello(frame, address, policyCache);
                }
                VerifiedPolicy verifiedPolicy = policy;
                Set<String> requestedFiles = requestedExplicitFiles(verifiedPolicy);
                if (!scheduleOrRollbackOnRuntimeFailure(() -> client.execute(() -> {
                    if (!authenticationAttempts.isActive(generation) || client.getNetworkHandler() == null) {
                        targetClaim.ifPresent(federationVault::cancelTargetClaim);
                        return;
                    }
                    if (targetClaim.isPresent()) {
                        Set<String> approved = targetClaim.orElseThrow().approvedExplicitFiles();
                        Optional<Set<String>> inheritedFiles =
                                MCAceEnablementController.inheritedFederationFiles(approved, requestedFiles);
                        if (inheritedFiles.isEmpty()) {
                            targetClaim.ifPresent(federationVault::cancelTargetClaim);
                            LOGGER.warn("MCAce federation target requested explicit files outside the one-time source approval; MCAce remains disabled");
                            return;
                        }
                        Set<String> allowed = inheritedFiles.orElseThrow();
                        enablementAuthorization = ConnectionEnablementAuthorization.federationInherited(
                                candidate, generation, targetClaim.orElseThrow());
                        explicitFileAuthorization = new ExplicitFileAuthorization(candidate, generation, allowed);
                        LOGGER.info("MCAce federation target connection enablement inherited from one-time source approval");
                        continueAuthentication(candidate, verifiedPolicy, client, generation, allowed);
                        return;
                    }
                    LOGGER.info("MCAce enablement consent requested for signed policy; explicit-file paths={}",
                            requestedFiles.size());
                    mcaceEnablement.request(client, verifiedPolicy, requestedFiles,
                            () -> LOGGER.info("MCAce enablement consent screen rendered"), allowed -> {
                        if (!authenticationAttempts.isActive(generation) || client.getNetworkHandler() == null) return;
                        enablementAuthorization = ConnectionEnablementAuthorization.humanVisible(
                                candidate, generation);
                        explicitFileAuthorization = new ExplicitFileAuthorization(candidate, generation, allowed);
                        LOGGER.info("MCAce enablement accepted for the current connection; no additional consent screens will be shown");
                        continueAuthentication(candidate, verifiedPolicy, client, generation, allowed);
                    }, () -> {
                        if (!authenticationAttempts.isActive(generation)) {
                            return;
                        }
                        enablementAuthorization = null;
                        explicitFileAuthorization = null;
                        LOGGER.info("MCAce enablement was declined; MCAce remains disabled and no client frame was sent");
                    });
                }), schedulingRollback)) {
                    LOGGER.warn("MCAce cancelled target enablement after client scheduling failed");
                }
            } catch (EnvelopeException | RuntimeException exception) {
                schedulingRollback.run();
                LOGGER.warn("MCAce rejected the signed challenge or policy: {}", exception.getMessage());
            }
        }), schedulingRollback)) {
            LOGGER.warn("MCAce cancelled target enablement after policy worker scheduling failed");
        }
    }

    private void continueAuthentication(ClientHandshakeEngine candidate, VerifiedPolicy verifiedPolicy,
            MinecraftClient client, long generation, Set<String> consentedExplicitFiles) {
        if (!candidate.isVerifiedPolicyCurrent(verifiedPolicy)) {
            cancelAuthentication(candidate, generation, "signed policy expired before integrity collection");
            return;
        }
        Set<String> authorizedFiles = Set.copyOf(consentedExplicitFiles);
        List<String> selectedResourcePacks = currentEnabledResourcePackIds(client);
        List<String> selectedShaderPacks = currentEnabledShaderPackIds();
        List<LoadedModObservation> loadedMods =
                FabricLoadedModObservationCollector.collect(FabricLoader.getInstance());
        authenticationIntegrityTask.submit(taskCancellation -> {
            IntegrityScanCancellation cancellation = () ->
                    taskCancellation.cancelled() || !authenticationAttempts.isActive(generation)
                            || !candidate.isVerifiedPolicyCurrent(verifiedPolicy)
                            || !isEnabled(candidate, generation)
                            || (!authorizedFiles.isEmpty()
                                    && !isAuthorized(candidate, generation, authorizedFiles));
            List<ClientHandshakeEngine.OutboundFrame> responses = List.of();
            try {
                cancellation.check();
                ClientIntegrityBundle bundle = new PolicyDrivenIntegrityCollector(Clock.systemUTC())
                        .collect(gameDirectory, verifiedPolicy.policy(), authorizedFiles, cancellation);
                cancellation.check();
                if (!authorizedFiles.isEmpty()) {
                    int explicitEntries = verifiedPolicy.policy().getIntegrityScopesList().stream()
                            .filter(rule -> rule.getExplicitRelativeFilesCount() > 0)
                            .map(rule -> bundle.scope(rule.getScope().toLowerCase(java.util.Locale.ROOT)))
                            .flatMap(Optional::stream)
                            .mapToInt(scope -> scope.entries().size())
                            .sum();
                    LOGGER.info("MCAce explicit-file manifest prepared entries={}", explicitEntries);
                }
                responses = candidate.createAuthenticationFrames(
                        bundle,
                        new ArtifactObservationCollector().collect(
                                gameDirectory, verifiedPolicy.policy(), bundle, cancellation),
                        selectedResourcePacks,
                        selectedShaderPacks,
                        loadedMods);
                cancellation.check();
                List<ClientHandshakeEngine.OutboundFrame> readyResponses = responses;
                client.execute(() -> {
                    if (!authenticationAttempts.isActive(generation) || !isEnabled(candidate, generation)
                            || !candidate.isVerifiedPolicyCurrent(verifiedPolicy)
                            || client.getNetworkHandler() == null
                            || (!authorizedFiles.isEmpty()
                                    && !isAuthorized(candidate, generation, authorizedFiles))) {
                        readyResponses.forEach(ClientHandshakeEngine.OutboundFrame::clear);
                        if (authenticationAttempts.isActive(generation)
                                && !candidate.isVerifiedPolicyCurrent(verifiedPolicy)) {
                            cancelAuthentication(candidate, generation,
                                    "signed policy expired before authentication send");
                        }
                        LOGGER.info("MCAce discarded a superseded authentication response");
                        return;
                    }
                    handshake = candidate;
                    if (!OrderedMCAceFrameSender.send(
                             readyResponses,
                             () -> authenticationAttempts.isActive(generation)
                                    && client.getNetworkHandler() != null
                                    && candidate.isVerifiedPolicyCurrent(verifiedPolicy),
                            new FabricFrameSink())) {
                        readyResponses.forEach(ClientHandshakeEngine.OutboundFrame::clear);
                        cancelAuthentication(candidate, generation,
                                "authentication frame delivery failed");
                        LOGGER.warn("MCAce stopped authentication frame delivery because the connection changed or a channel was unavailable");
                        return;
                    }
                    lastReportedResourcePacks = selectedResourcePacks;
                    lastReportedShaderPacks = selectedShaderPacks;
                    lastReportedLoadedMods = loadedMods;
                    LOGGER.info("MCAce answered signed policy {} sequence {} with {} scoped manifests",
                            verifiedPolicy.policy().getPolicyVersion(), verifiedPolicy.policy().getSequence(),
                            bundle.scopes().size());
                });
            } catch (EnvelopeException | IntegrityScanException | RuntimeException exception) {
                responses.forEach(ClientHandshakeEngine.OutboundFrame::clear);
                boolean cancelled = cancellation.cancelled();
                client.execute(() -> cancelAuthentication(
                        candidate,
                        generation,
                        cancelled
                                ? "superseded or expired integrity collection"
                                : "scoped integrity collection failed"));
                if (cancelled) {
                    LOGGER.debug("MCAce cancelled a superseded scoped integrity read");
                } else {
                    LOGGER.warn("MCAce rejected the scoped integrity request: {}", exception.getMessage());
                }
            }
        });
    }

    private static Set<String> requestedExplicitFiles(VerifiedPolicy verifiedPolicy) {
        return verifiedPolicy.policy().getIntegrityScopesList().stream()
                .flatMap(rule -> rule.getExplicitRelativeFilesList().stream())
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    private boolean isAuthorized(ClientHandshakeEngine candidate, long generation, Set<String> files) {
        ExplicitFileAuthorization authorization = explicitFileAuthorization;
        return authorization != null && authorization.candidate() == candidate
                && authorization.generation() == generation && authorization.files().equals(files);
    }

    private boolean isEnabled(ClientHandshakeEngine candidate, long generation) {
        ConnectionEnablementAuthorization authorization = enablementAuthorization;
        return authorization != null
                && authorization.matches(candidate, generation, federationVault, Clock.systemUTC());
    }

    private boolean isConnectionBoundEnabled(ClientHandshakeEngine candidate, long generation) {
        ConnectionEnablementAuthorization authorization = enablementAuthorization;
        return authorization != null
                && authorization.isConnectionBound(
                        candidate, generation, federationVault, Clock.systemUTC());
    }

    private void receiveAuthResult(
            SignedEnvelope envelope,
            MCAcePayload payload,
            ClientPlayNetworking.Context context) {
        ClientHandshakeEngine candidate = handshake;
        if (candidate == null) {
            LOGGER.warn("MCAce received an authentication result without an active handshake");
            return;
        }
        long attempt = authenticationAttempts.activeAttempt();
        try {
            if (!authenticationAttempts.isActive(attempt) || handshake != candidate
                    || !candidate.verifiedSessionId().equals(envelope.getHeader().getSessionId())) {
                LOGGER.info("MCAce ignored an authentication result for a superseded session");
                return;
            }
            com.ellan.mcace.protocol.generated.AuthResult result = candidate.receiveAuthResult(payload.data());
            if (result.getAccepted()) {
                LOGGER.info("MCAce session verified at trust level {} with risk score {}",
                        result.getTrustLevel(), result.getRiskScore());
                if (authenticationAttempts.isActive(attempt) && handshake == candidate && candidate.heartbeatReady()) {
                    ConnectionEnablementAuthorization authorization = enablementAuthorization;
                    if (authorization != null && authorization.isInheritedProvisional()) {
                        requestFederationImportConsent(candidate, context.client(), attempt);
                    } else if (isConnectionBoundEnabled(candidate, attempt)) {
                        heartbeatSchedule.activate(attempt);
                        observationSchedule.activate(attempt);
                        requestFederationImportConsent(candidate, context.client(), attempt);
                    } else {
                        cancelAuthentication(candidate, attempt,
                                "authentication result has no live enablement authorization");
                    }
                } else {
                    // A connection transition raced the result. Never let it revive an old session.
                    cancelAuthentication(candidate, attempt, "superseded authentication result");
                }
            } else {
                LOGGER.warn("MCAce authentication was declined: {}", result.getReasonCodesList());
                cancelAuthentication(candidate, attempt, "authentication declined");
            }
            if (shouldStopPlatformSmokeAfterAuthentication(
                    Boolean.getBoolean("mcace.platform-smoke.exit-on-auth-result"),
                    Boolean.getBoolean("mcace.platform-smoke.await-evidence"))) {
                LOGGER.info("MCAce platform smoke received an authentication result; scheduling client shutdown");
                context.client().scheduleStop();
            } else if (Boolean.getBoolean("mcace.platform-smoke.await-evidence")) {
                LOGGER.info("MCAce platform evidence smoke verified; waiting for a signed GAME_RENDER_FRAME request");
            }
        } catch (EnvelopeException exception) {
            LOGGER.warn("MCAce rejected the authentication result: {}", exception.getMessage());
            cancelAuthentication(candidate, attempt, "invalid authentication result");
        }
    }

    private void receiveArtifactObservationResult(MCAcePayload payload) {
        PendingArtifactObservationUpdate pending = pendingArtifactObservationUpdate;
        if (pending == null) {
            LOGGER.debug("MCAce ignored an artifact observation result without a pending update");
            return;
        }
        ClientHandshakeEngine candidate = pending.candidate();
        long attempt = pending.attempt();
        if (!authenticationAttempts.isActive(attempt) || handshake != candidate
                || !observationSchedule.isActive(attempt)
                || !isConnectionBoundEnabled(candidate, attempt)) {
            LOGGER.debug("MCAce ignored an artifact observation result for a superseded session");
            return;
        }
        try {
            ClientHandshakeEngine.VerifiedArtifactObservationResult result =
                    candidate.receiveArtifactObservationResult(payload.data(), pending.prepared());
            pendingArtifactObservationUpdate = null;
            if (result.accepted()) {
                try {
                    candidate.commitArtifactObservationUpdate(pending.prepared());
                    lastReportedResourcePacks = pending.resourcePacks();
                    lastReportedShaderPacks = pending.shaderPacks();
                    lastReportedLoadedMods = pending.loadedMods();
                    observationSchedule.complete(attempt);
                    LOGGER.debug("MCAce accepted signed artifact observation result sequence {}",
                            result.updateSequence());
                } catch (EnvelopeException exception) {
                    observationSchedule.fail(attempt);
                    LOGGER.warn("MCAce retained a dirty artifact observation after commit failed: {}",
                            exception.getMessage());
                }
            } else {
                if (result.reason()
                        == ArtifactObservationResultReason.ARTIFACT_OBSERVATION_RESULT_RATE_LIMITED) {
                    observationSchedule.retryAt(attempt, result.retryAfterEpochMs());
                } else {
                    observationSchedule.fail(attempt);
                }
                LOGGER.info("MCAce server rejected artifact observation sequence {} with reason {}; a fresh snapshot remains scheduled",
                        result.updateSequence(), result.reason());
            }
        } catch (EnvelopeException exception) {
            // A forged, stale, replayed, or mis-bound result cannot mutate local root/sequence.
            // Keep waiting for the authentic result; timeout handling will retry the exact payload.
            LOGGER.warn("MCAce ignored an invalid artifact observation result: {}", exception.getMessage());
        }
    }

    private void receiveFederationConsentRequest(MCAcePayload payload, ClientPlayNetworking.Context context) {
        ClientHandshakeEngine candidate = handshake;
        if (candidate == null) return;
        try {
            ClientHandshakeEngine.VerifiedFederationConsentRequest request =
                    candidate.receiveFederationConsentRequest(payload.data());
            long attempt = authenticationAttempts.activeAttempt();
            ConnectionEnablementAuthorization authorization = enablementAuthorization;
            byte[] requestIdentity = request.requestPayloadSha256();
            if (!isConnectionBoundEnabled(candidate, attempt) || authorization == null
                    || !authorization.tryBeginSourceExport(
                            request.request().getAssertionId(), requestIdentity)) {
                LOGGER.warn("MCAce rejected federation source export because its one-shot human approval is absent, consumed, or inherited");
                return;
            }
            LOGGER.info("MCAce reserved the connection's single federation source export permit");
            sendAllowedFederationConsent(
                    candidate, context.client(), request, requestIdentity, authorization, attempt);
        } catch (EnvelopeException exception) {
            LOGGER.warn("MCAce rejected a federation consent request: {}", exception.getMessage());
        }
    }

    private void sendAllowedFederationConsent(
            ClientHandshakeEngine candidate, MinecraftClient client,
            ClientHandshakeEngine.VerifiedFederationConsentRequest request,
            byte[] requestIdentity,
            ConnectionEnablementAuthorization authorization,
            long attempt) {
        String assertionId = request.request().getAssertionId();
        Runnable rollback = () -> {
            try {
                candidate.cancelFederationConsent(request);
            } finally {
                authorization.releaseSourceExportAfterLocalFailure(assertionId, requestIdentity);
            }
        };
        if (!scheduleOrRollbackOnRuntimeFailure(
                () -> Thread.ofVirtual().name("mcace-federation-consent").start(() -> {
                    if (!runFederationWorkerOrRollback(() -> {
                        byte[] response = candidate.createFederationConsentFrame(request);
                        if (!scheduleOrRollbackOnRuntimeFailure(() -> client.execute(() -> {
                            if (!authenticationAttempts.isActive(attempt)
                                    || !isConnectionBoundEnabled(candidate, attempt)
                                    || handshake != candidate || client.getNetworkHandler() == null
                                    || !ClientPlayNetworking.canSend(MCAcePayload.ID)) {
                                rollback.run();
                                return;
                            }
                            try {
                                ClientPlayNetworking.send(new MCAcePayload(response));
                                if (!authorization.commitSourceExport(assertionId, requestIdentity)) {
                                    LOGGER.warn("MCAce source export was handed to transport after its connection authorization changed");
                                }
                            } catch (RuntimeException exception) {
                                rollback.run();
                            }
                        }), rollback)) {
                            LOGGER.warn("MCAce rolled back the exact federation source export after client scheduling failed");
                        }
                    }, rollback)) {
                        LOGGER.warn("MCAce rolled back the exact federation source export after worker execution failed");
                    }
                }), rollback)) {
            LOGGER.warn("MCAce rolled back the exact federation source export after worker scheduling failed");
        }
    }

    static boolean scheduleOrRollbackOnRuntimeFailure(Runnable schedule, Runnable rollback) {
        java.util.Objects.requireNonNull(schedule, "schedule");
        java.util.Objects.requireNonNull(rollback, "rollback");
        try {
            schedule.run();
            return true;
        } catch (RuntimeException exception) {
            rollback.run();
            return false;
        }
    }

    static boolean runFederationWorkerOrRollback(
            FederationWorkerStep worker, Runnable rollback) {
        java.util.Objects.requireNonNull(worker, "worker");
        java.util.Objects.requireNonNull(rollback, "rollback");
        try {
            worker.run();
            return true;
        } catch (EnvelopeException | RuntimeException exception) {
            rollback.run();
            return false;
        }
    }

    @FunctionalInterface
    interface FederationWorkerStep {
        void run() throws EnvelopeException;
    }

    private void receiveFederationGrant(MCAcePayload payload, ClientPlayNetworking.Context context) {
        ClientHandshakeEngine candidate = handshake;
        if (candidate == null) return;
        try {
            long generation = authenticationAttempts.activeAttempt();
            ExplicitFileAuthorization authorization = explicitFileAuthorization;
            ConnectionEnablementAuthorization connectionAuthorization = enablementAuthorization;
            if (!isConnectionBoundEnabled(candidate, generation) || handshake != candidate
                    || authorization == null || connectionAuthorization == null
                    || authorization.candidate() != candidate || authorization.generation() != generation) {
                LOGGER.warn("MCAce ignored a federation grant because its source enablement scope is absent");
                return;
            }
            candidate.receiveFederationGrant(
                    payload.data(), federationVault, authorization.files(), connectionAuthorization);
            LOGGER.info("MCAce stored a one-time federation grant in memory only");
        } catch (EnvelopeException exception) {
            LOGGER.warn("MCAce rejected a federation grant: {}", exception.getMessage());
        }
    }

    private void requestFederationImportConsent(
            ClientHandshakeEngine candidate, MinecraftClient client, long attempt) {
        Runnable schedulingRollback = () -> rollbackFederationPresentation(
                candidate, attempt, null, "federation presentation worker scheduling failed");
        if (!scheduleOrRollbackOnRuntimeFailure(
                () -> Thread.ofVirtual().name("mcace-federation-presentation").start(() -> {
                    FederationTokenVault.PreparedPresentation prepared = null;
                    try {
                        ClientPlayNetworkHandler networkHandler = client.getNetworkHandler();
                        if (networkHandler == null || networkHandler.getProfile() == null) {
                            Runnable rollback = () -> rollbackFederationPresentation(
                                    candidate,
                                    attempt,
                                    null,
                                    "federation presentation connection was unavailable");
                            scheduleOrRollbackOnRuntimeFailure(
                                    () -> client.execute(rollback), rollback);
                            return;
                        }
                        prepared = federationVault.preparePresentation(
                                candidate.authenticatedServerId(),
                                networkHandler.getProfile().id(),
                                candidate.authenticatedSessionId(),
                                candidate.federationChallengeNonce(),
                                Clock.systemUTC()).orElse(null);
                        if (prepared == null) {
                            Runnable rollback = () -> rollbackFederationPresentation(
                                    candidate,
                                    attempt,
                                    null,
                                    "federation presentation was unavailable");
                            scheduleOrRollbackOnRuntimeFailure(
                                    () -> client.execute(rollback), rollback);
                            return;
                        }
                        FederationTokenVault.PreparedPresentation reserved = prepared;
                        Runnable rollback = () -> rollbackFederationPresentation(
                                candidate,
                                attempt,
                                reserved,
                                "federation presentation client scheduling failed");
                        if (!scheduleOrRollbackOnRuntimeFailure(() -> client.execute(() -> {
                            if (!authenticationAttempts.isActive(attempt)
                                    || !isEnabled(candidate, attempt)
                                    || handshake != candidate
                                    || client.getNetworkHandler() == null
                                    || !ClientPlayNetworking.canSend(MCAcePayload.ID)) {
                                rollbackFederationPresentation(
                                        candidate,
                                        attempt,
                                        reserved,
                                        "federation presentation connection changed");
                                return;
                            }
                            if (!federationVault.isReserved(reserved, Clock.systemUTC())) {
                                rollbackFederationPresentation(
                                        candidate,
                                        attempt,
                                        reserved,
                                        "federation presentation reservation expired");
                                return;
                            }
                            LOGGER.info("MCAce federation target import consent inherited from connection enablement");
                            sendAllowedFederationPresentation(candidate, client, attempt, reserved);
                        }), rollback)) {
                            LOGGER.warn("MCAce aborted the provisional federation target after import scheduling failed");
                        }
                    } catch (Exception exception) {
                        rollbackFederationPresentation(
                                candidate,
                                attempt,
                                prepared,
                                "federation presentation preparation failed");
                        LOGGER.debug("MCAce federation presentation is unavailable: {}", exception.getMessage());
                    }
                }), schedulingRollback)) {
            LOGGER.warn("MCAce aborted the provisional federation target after worker scheduling failed");
        }
    }

    private void sendAllowedFederationPresentation(ClientHandshakeEngine candidate,
            MinecraftClient client, long attempt, FederationTokenVault.PreparedPresentation prepared) {
        Runnable rollback = () -> rollbackFederationPresentation(
                candidate, attempt, prepared, "federation presentation send scheduling failed");
        if (!scheduleOrRollbackOnRuntimeFailure(
                () -> Thread.ofVirtual().name("mcace-federation-presentation-send").start(() -> {
                    try {
                        if (!federationVault.isReserved(prepared, Clock.systemUTC())) {
                            rollbackFederationPresentation(
                                    candidate,
                                    attempt,
                                    prepared,
                                    "federation presentation reservation expired before signing");
                            return;
                        }
                        byte[] frame = candidate.createFederationPresentationFrame(prepared.encoded());
                        if (!scheduleOrRollbackOnRuntimeFailure(() -> client.execute(() -> {
                            if (!authenticationAttempts.isActive(attempt) || handshake != candidate
                                    || client.getNetworkHandler() == null
                                    || !ClientPlayNetworking.canSend(MCAcePayload.ID)) {
                                rollbackFederationPresentation(
                                        candidate,
                                        attempt,
                                        prepared,
                                        "federation presentation connection changed");
                                return;
                            }
                            if (!federationVault.isReserved(prepared, Clock.systemUTC())) {
                                rollbackFederationPresentation(
                                        candidate,
                                        attempt,
                                        prepared,
                                        "federation presentation reservation expired before send");
                                return;
                            }
                            try {
                                ClientPlayNetworking.send(new MCAcePayload(frame));
                                Optional<FederationTokenVault.PresentationCommitReceipt> receipt =
                                        federationVault.commit(prepared, Clock.systemUTC());
                                if (receipt.isEmpty()
                                        || !promoteFederationAuthorization(
                                                candidate, attempt, receipt.orElseThrow())) {
                                    rollbackFederationPresentation(
                                            candidate,
                                            attempt,
                                            prepared,
                                            "federation presentation commit failed");
                                    return;
                                }
                                heartbeatSchedule.activate(attempt);
                                observationSchedule.activate(attempt);
                                LOGGER.info("MCAce federation target authorization promoted to the current connection after one-time presentation commit");
                            } catch (RuntimeException exception) {
                                rollbackFederationPresentation(
                                        candidate,
                                        attempt,
                                        prepared,
                                        "federation presentation send failed");
                            }
                        }), rollback)) {
                            LOGGER.warn("MCAce aborted the provisional federation target after presentation client scheduling failed");
                        }
                    } catch (EnvelopeException | RuntimeException exception) {
                        rollbackFederationPresentation(
                                candidate,
                                attempt,
                                prepared,
                                "federation presentation signing failed");
                        LOGGER.debug("MCAce federation presentation send was cancelled: {}", exception.getMessage());
                    }
                }), rollback)) {
            LOGGER.warn("MCAce aborted the provisional federation target after presentation worker scheduling failed");
        }
    }

    private void rollbackFederationPresentation(
            ClientHandshakeEngine candidate,
            long attempt,
            FederationTokenVault.PreparedPresentation prepared,
            String reason) {
        try {
            federationVault.sendFailed(prepared);
        } finally {
            abortProvisionalFederationAuthorization(candidate, attempt, reason);
        }
    }

    private boolean promoteFederationAuthorization(
            ClientHandshakeEngine candidate,
            long attempt,
            FederationTokenVault.PresentationCommitReceipt receipt) {
        ConnectionEnablementAuthorization authorization = enablementAuthorization;
        return authorization != null
                && authenticationAttempts.isActive(attempt)
                && handshake == candidate
                && authorization.promoteAfterPresentationCommit(receipt);
    }

    private void abortProvisionalFederationAuthorization(
            ClientHandshakeEngine candidate, long attempt, String reason) {
        ConnectionEnablementAuthorization authorization = enablementAuthorization;
        if (authorization != null && authorization.isInheritedProvisional()
                && authenticationAttempts.isActive(attempt) && handshake == candidate) {
            cancelAuthentication(candidate, attempt, reason);
        }
    }

    private void receiveEvidenceRequest(MCAcePayload payload, ClientPlayNetworking.Context context) {
        ClientHandshakeEngine candidate = handshake;
        long attempt = authenticationAttempts.activeAttempt();
        ConnectionEnablementAuthorization authorization = enablementAuthorization;
        if (candidate == null || !candidate.heartbeatReady()
                || authorization == null || !isConnectionBoundEnabled(candidate, attempt)) {
            LOGGER.warn("MCAce ignored an evidence request without an authenticated session");
            return;
        }
        try {
            ClientHandshakeEngine.VerifiedEvidenceRequest request = candidate.receiveEvidenceRequest(payload.data());
            if (!authorization.tryBeginEvidenceCapture(request.requestId(), request.evidenceId())) {
                candidate.cancelEvidenceRequest(request);
                LOGGER.warn("MCAce rejected an evidence request because this connection's one-frame budget is absent, busy, or consumed");
                return;
            }
            try {
                evidenceCapture.accept(context.client(), request,
                        new EvidenceSender(context.client(), candidate, authorization, attempt), true);
            } catch (RuntimeException exception) {
                authorization.releaseEvidenceCaptureWithoutContent(request.requestId(), request.evidenceId());
                candidate.cancelEvidenceRequest(request);
                throw exception;
            }
            if (request.captureScope() == com.ellan.mcace.protocol.generated.EvidenceCaptureScope.GAME_RENDER_FRAME) {
                LOGGER.info("MCAce evidence request accepted under connection enablement; no second consent screen");
            }
        } catch (EnvelopeException | RuntimeException exception) {
            LOGGER.warn("MCAce rejected the evidence request: {}", exception.getMessage());
        }
    }

    private void receiveEvidenceAck(MCAcePayload payload, ClientPlayNetworking.Context context) {
        ClientHandshakeEngine candidate = handshake;
        if (candidate == null) {
            return;
        }
        try {
            ClientHandshakeEngine.VerifiedEvidenceAck verified = candidate.receiveEvidenceAck(payload.data());
            if (verified.ack().getStatus()
                    == com.ellan.mcace.protocol.generated.EvidenceAckStatus.EVIDENCE_ACK_COMPLETE) {
                dropQueuedEvidenceFrames(verified.request());
                candidate.completeEvidenceRequest(verified.request());
                LOGGER.info("MCAce evidence transfer COMPLETE request={}", verified.request().requestId());
                if (shouldStopPlatformSmokeAfterEvidence(
                        Boolean.getBoolean("mcace.platform-smoke.exit-on-evidence-complete"))) {
                    context.client().scheduleStop();
                }
            }
        } catch (EnvelopeException exception) {
            LOGGER.warn("MCAce rejected the evidence ACK: {}", exception.getMessage());
        }
    }

    private void receiveEvidenceError(MCAcePayload payload, ClientPlayNetworking.Context context) {
        ClientHandshakeEngine candidate = handshake;
        if (candidate == null) {
            return;
        }
        try {
            ClientHandshakeEngine.VerifiedEvidenceError verified = candidate.receiveEvidenceError(payload.data());
            removeQueuedEvidenceFrames(verified.request());
            candidate.cancelEvidenceRequest(verified.request());
            LOGGER.warn("MCAce evidence request was rejected by the server: {}",
                    verified.error().getCode());
        } catch (EnvelopeException exception) {
            LOGGER.warn("MCAce rejected the evidence ERROR: {}", exception.getMessage());
        }
    }

    private static ServerKeyPins loadPins(Path path) {
        try {
            return ServerKeyPins.load(path);
        } catch (IOException | EnvelopeException exception) {
            LOGGER.error("MCAce could not load server key pins from {}", path, exception);
            return ServerKeyPins.none();
        }
    }

    static boolean shouldStopPlatformSmokeAfterAuthentication(boolean exitOnAuthResult,
            boolean awaitEvidence) {
        return exitOnAuthResult && !awaitEvidence;
    }

    static boolean shouldStopPlatformSmokeAfterEvidence(boolean exitOnEvidenceComplete) {
        return exitOnEvidenceComplete;
    }

    private void cancelAuthentication(
            ClientHandshakeEngine candidate,
            long generation,
            String reason) {
        if (!authenticationAttempts.isActive(generation)) {
            LOGGER.debug("MCAce ignored cancellation from superseded generation {}: {}", generation, reason);
            return;
        }
        ConnectionEnablementAuthorization authorization = enablementAuthorization;
        if (authorization != null && !authorization.owns(candidate, generation)) {
            LOGGER.debug("MCAce ignored cancellation for a different enablement capability: {}", reason);
            return;
        }
        ClientHandshakeEngine activeHandshake = handshake;
        if (activeHandshake != null && activeHandshake != candidate) {
            LOGGER.debug("MCAce ignored cancellation for a different handshake: {}", reason);
            return;
        }
        cancelAuthentication(reason);
    }

    private void invalidateAndCancelTargetClaim(ConnectionEnablementAuthorization authorization) {
        if (authorization == null) {
            return;
        }
        if (authorization.origin() == ConnectionEnablementAuthorization.Origin.FEDERATION_INHERITED) {
            federationVault.cancelTargetClaim(authorization.targetClaim());
        }
        authorization.invalidate();
    }

    private void cancelAuthentication(String reason) {
        invalidateAndCancelTargetClaim(enablementAuthorization);
        federationVault.cancelTargetClaims();
        authenticationAttempts.cancel();
        authenticationIntegrityTask.cancel();
        observationIntegrityTask.cancel();
        cancelQueuedEvidenceFrames();
        if (evidenceCapture != null) {
            evidenceCapture.cancel(MinecraftClient.getInstance());
        }
        mcaceEnablement.cancel(MinecraftClient.getInstance());
        explicitFileConsent.cancel(MinecraftClient.getInstance());
        enablementAuthorization = null;
        explicitFileAuthorization = null;
        heartbeatSchedule.cancel();
        observationSchedule.cancel();
        pendingArtifactObservationUpdate = null;
        pendingChallenge = null;
        handshake = null;
        lastReportedResourcePacks = List.of();
        lastReportedShaderPacks = List.of();
        lastReportedLoadedMods = List.of();
        LOGGER.debug("MCAce cancelled pending authentication: {}", reason);
    }

    private final class EvidenceSender implements EvidenceCaptureController.Sender {
        private final MinecraftClient client;
        private final ClientHandshakeEngine candidate;
        private final ConnectionEnablementAuthorization authorization;
        private final long attempt;

        private EvidenceSender(MinecraftClient client, ClientHandshakeEngine candidate,
                ConnectionEnablementAuthorization authorization, long attempt) {
            this.client = client;
            this.candidate = candidate;
            this.authorization = authorization;
            this.attempt = attempt;
        }

        @Override
        public void sendOutcome(ClientHandshakeEngine.VerifiedEvidenceRequest request,
                EvidenceCollectionStatus status) {
            authorization.releaseEvidenceCaptureWithoutContent(request.requestId(), request.evidenceId());
            Thread.ofVirtual().name("mcace-evidence-outcome").start(() -> {
                List<ClientHandshakeEngine.OutboundFrame> frames = null;
                try {
                    frames = candidate.createEvidenceResponseFrames(request, status);
                    final List<ClientHandshakeEngine.OutboundFrame> prepared = frames;
                    client.execute(() -> enqueueEvidenceFrames(request, prepared));
                } catch (EnvelopeException | RuntimeException exception) {
                    if (frames != null) {
                        clearEvidenceFrames(frames);
                    }
                    candidate.cancelEvidenceRequest(request);
                    LOGGER.debug("MCAce could not prepare evidence outcome: {}", exception.getMessage());
                }
            });
        }

        @Override
        public void sendFrame(ClientHandshakeEngine.VerifiedEvidenceRequest request, long capturedAtEpochMs,
                int widthPixels, int heightPixels, byte[] encodedContent) {
            if (!authorization.commitEvidenceCapture(request.requestId(), request.evidenceId())) {
                Arrays.fill(encodedContent, (byte) 0);
                candidate.cancelEvidenceRequest(request);
                return;
            }
            Thread.ofVirtual().name("mcace-evidence-transfer").start(() -> {
                List<ClientHandshakeEngine.OutboundFrame> frames = null;
                try {
                    ClientHandshakeEngine.EvidenceConsentGrant consent =
                            candidate.grantEvidenceConsent(request);
                    frames = candidate.createEvidenceTransferFrames(
                            request, consent, capturedAtEpochMs, widthPixels, heightPixels, encodedContent);
                    final List<ClientHandshakeEngine.OutboundFrame> prepared = frames;
                    client.execute(() -> enqueueEvidenceFrames(request, prepared));
                } catch (EnvelopeException | RuntimeException exception) {
                    if (frames != null) {
                        clearEvidenceFrames(frames);
                    }
                    candidate.cancelEvidenceRequest(request);
                    LOGGER.debug("MCAce could not prepare evidence transfer: {}", exception.getMessage());
                } finally {
                    Arrays.fill(encodedContent, (byte) 0);
                }
            });
        }

        @Override
        public void cancel(ClientHandshakeEngine.VerifiedEvidenceRequest request) {
            authorization.releaseEvidenceCaptureWithoutContent(request.requestId(), request.evidenceId());
            removeQueuedEvidenceFrames(request);
            candidate.cancelEvidenceRequest(request);
        }

        @Override
        public void screenRendered(ClientHandshakeEngine.VerifiedEvidenceRequest request) {
            LOGGER.info("MCAce legacy standalone evidence consent screen rendered for signed GAME_RENDER_FRAME request");
        }

        @Override
        public void consentAllowed(ClientHandshakeEngine.VerifiedEvidenceRequest request) {
            LOGGER.info("MCAce evidence consent inherited from connection enablement for signed GAME_RENDER_FRAME request");
        }

        private void enqueueEvidenceFrames(ClientHandshakeEngine.VerifiedEvidenceRequest request,
                List<ClientHandshakeEngine.OutboundFrame> frames) {
            if (!authenticationAttempts.isActive(attempt)
                    || !isConnectionBoundEnabled(candidate, attempt)
                    || handshake != candidate) {
                clearEvidenceFrames(frames);
                candidate.cancelEvidenceRequest(request);
                return;
            }
            try {
                evidenceFrames.addLast(new QueuedEvidenceFrames(request, candidate, attempt, List.copyOf(frames)));
            } catch (RuntimeException exception) {
                clearEvidenceFrames(frames);
                candidate.cancelEvidenceRequest(request);
                throw exception;
            }
        }
    }

    private static void clearEvidenceFrames(List<ClientHandshakeEngine.OutboundFrame> frames) {
        frames.forEach(ClientHandshakeEngine.OutboundFrame::clear);
    }

    /** Sends at most eight evidence frames per client tick and waits for server COMPLETE. */
    private void pumpEvidenceFrames(MinecraftClient client) {
        int budget = 8;
        while (budget-- > 0 && !evidenceFrames.isEmpty()) {
            QueuedEvidenceFrames queued = evidenceFrames.peekFirst();
            if (!authenticationAttempts.isActive(queued.attempt())
                    || !isConnectionBoundEnabled(queued.candidate(), queued.attempt())
                    || handshake != queued.candidate()
                    || client.getNetworkHandler() == null) {
                evidenceFrames.removeFirst();
                queued.clear();
                queued.candidate().cancelEvidenceRequest(queued.request());
                continue;
            }
            ClientHandshakeEngine.OutboundFrame frame = queued.frames().get(queued.nextIndex());
            FabricFrameSink sink = new FabricFrameSink();
            if (!sink.canSend(frame)) {
                evidenceFrames.removeFirst();
                queued.clear();
                queued.candidate().cancelEvidenceRequest(queued.request());
                LOGGER.debug("MCAce cancelled evidence transfer because its channel is unavailable");
                continue;
            }
            try {
                sink.send(frame);
                frame.clear();
                queued.advance();
            } catch (RuntimeException exception) {
                evidenceFrames.removeFirst();
                queued.clear();
                queued.candidate().cancelEvidenceRequest(queued.request());
                LOGGER.debug("MCAce cancelled evidence transfer after send failure: {}", exception.getMessage());
                continue;
            }
            if (queued.complete()) {
                evidenceFrames.removeFirst();
                queued.clear();
            }
        }
    }

    private void cancelQueuedEvidenceFrames() {
        while (!evidenceFrames.isEmpty()) {
            QueuedEvidenceFrames queued = evidenceFrames.removeFirst();
            queued.clear();
            queued.candidate().cancelEvidenceRequest(queued.request());
        }
    }

    private void removeQueuedEvidenceFrames(ClientHandshakeEngine.VerifiedEvidenceRequest request) {
        Iterator<QueuedEvidenceFrames> iterator = evidenceFrames.iterator();
        while (iterator.hasNext()) {
            QueuedEvidenceFrames queued = iterator.next();
            if (queued.request().requestId().equals(request.requestId())) {
                iterator.remove();
                queued.clear();
                queued.candidate().cancelEvidenceRequest(queued.request());
            }
        }
    }

    private void dropQueuedEvidenceFrames(ClientHandshakeEngine.VerifiedEvidenceRequest request) {
        Iterator<QueuedEvidenceFrames> iterator = evidenceFrames.iterator();
        while (iterator.hasNext()) {
            QueuedEvidenceFrames queued = iterator.next();
            if (queued.request().requestId().equals(request.requestId())) {
                iterator.remove();
                queued.clear();
            }
        }
    }

    private static final class QueuedEvidenceFrames {
        private final ClientHandshakeEngine.VerifiedEvidenceRequest request;
        private final ClientHandshakeEngine candidate;
        private final long attempt;
        private final List<ClientHandshakeEngine.OutboundFrame> frames;
        private int nextIndex;

        private QueuedEvidenceFrames(ClientHandshakeEngine.VerifiedEvidenceRequest request,
                ClientHandshakeEngine candidate, long attempt,
                List<ClientHandshakeEngine.OutboundFrame> frames) {
            this.request = request;
            this.candidate = candidate;
            this.attempt = attempt;
            this.frames = frames;
        }

        private ClientHandshakeEngine.VerifiedEvidenceRequest request() { return request; }
        private ClientHandshakeEngine candidate() { return candidate; }
        private long attempt() { return attempt; }
        private List<ClientHandshakeEngine.OutboundFrame> frames() { return frames; }
        private int nextIndex() { return nextIndex; }
        private void advance() { nextIndex++; }
        private boolean complete() { return nextIndex >= frames.size(); }

        private void clear() {
            clearEvidenceFrames(frames);
        }
    }

    /**
     * Tick only checks a monotonic deadline. Signing occurs on a virtual thread and the actual
     * plugin-message write returns to Fabric's client executor, so no render tick reads files or
     * performs cryptographic work.
     */
    private void scheduleHeartbeat(MinecraftClient client) {
        long attempt = authenticationAttempts.activeAttempt();
        ClientHandshakeEngine candidate = handshake;
        if (candidate == null || !candidate.heartbeatReady()
                || !isConnectionBoundEnabled(candidate, attempt)) {
            if (heartbeatSchedule.isActive(attempt)) {
                heartbeatSchedule.cancel();
            }
            return;
        }
        if (!heartbeatSchedule.takeDue(attempt)) {
            return;
        }
        Thread.ofVirtual().name("mcace-heartbeat").start(() -> {
            final byte[] frame;
            try {
                frame = candidate.createHeartbeat();
            } catch (EnvelopeException | RuntimeException exception) {
                heartbeatSchedule.cancel();
                LOGGER.warn("MCAce stopped heartbeat delivery because signing failed: {}", exception.getMessage());
                return;
            }
            client.execute(() -> {
                if (!authenticationAttempts.isActive(attempt)
                        || !isConnectionBoundEnabled(candidate, attempt)
                        || handshake != candidate
                        || !heartbeatSchedule.isActive(attempt)
                        || client.getNetworkHandler() == null
                        || !ClientPlayNetworking.canSend(MCAcePayload.ID)) {
                    heartbeatSchedule.cancel();
                    return;
                }
                try {
                    // HEARTBEAT is a signed envelope on the established handshake channel.
                    ClientPlayNetworking.send(new MCAcePayload(frame));
                    heartbeatSchedule.complete(attempt);
                } catch (RuntimeException exception) {
                    heartbeatSchedule.cancel();
                    LOGGER.warn("MCAce stopped heartbeat delivery because the channel failed: {}", exception.getMessage());
                }
            });
        });
    }

    /**
     * Re-scans only the signed policy scopes after authentication. This work is intentionally
     * outside the client tick and the resulting optional observation never captures the desktop,
     * game window, or files outside Minecraft's explicitly allowed integrity roots.
     */
    private void scheduleArtifactObservation(MinecraftClient client) {
        long attempt = authenticationAttempts.activeAttempt();
        ClientHandshakeEngine candidate = handshake;
        if (candidate == null || !candidate.heartbeatReady()
                || !isConnectionBoundEnabled(candidate, attempt)) {
            if (observationSchedule.isActive(attempt)) {
                observationSchedule.cancel();
                pendingArtifactObservationUpdate = null;
            }
            return;
        }
        if (observationSchedule.timeoutIfDue(attempt, ProtocolConstants.DEFAULT_CLOCK_SKEW)) {
            LOGGER.info("MCAce artifact observation result timed out; retaining the exact update for bounded retry");
        }
        List<String> selectedResourcePacks = currentEnabledResourcePackIds(client);
        List<String> selectedShaderPacks = currentEnabledShaderPackIds();
        List<LoadedModObservation> loadedMods =
                FabricLoadedModObservationCollector.collect(FabricLoader.getInstance());
        boolean runtimeStateChanged = selectedPackOrderChanged(selectedResourcePacks, lastReportedResourcePacks)
                || !selectedShaderPacks.equals(lastReportedShaderPacks)
                || !loadedMods.equals(lastReportedLoadedMods);
        if (!observationSchedule.takeDue(attempt, runtimeStateChanged)) return;

        PendingArtifactObservationUpdate pending = pendingArtifactObservationUpdate;
        if (pending != null) {
            if (pending.candidate() != candidate || pending.attempt() != attempt) {
                pendingArtifactObservationUpdate = null;
                observationSchedule.fail(attempt);
                return;
            }
            retryPendingArtifactObservation(client, pending);
            return;
        }

        ExplicitFileAuthorization authorization = explicitFileAuthorization;
        Set<String> authorizedFiles = authorization != null && authorization.candidate() == candidate
                && authorization.generation() == attempt ? authorization.files() : Set.of();
        try {
            observationIntegrityTask.submit(taskCancellation -> {
                IntegrityScanCancellation cancellation = () ->
                        taskCancellation.cancelled() || !authenticationAttempts.isActive(attempt)
                                || !observationSchedule.isActive(attempt)
                                || (!authorizedFiles.isEmpty()
                                        && !isAuthorized(candidate, attempt, authorizedFiles));
                ClientHandshakeEngine.PreparedArtifactObservationUpdate prepared = null;
                try {
                    cancellation.check();
                    prepared = candidate.prepareRescannedArtifactObservationUpdate(
                            gameDirectory, authorizedFiles, selectedResourcePacks, selectedShaderPacks,
                            loadedMods, cancellation);
                    cancellation.check();
                } catch (EnvelopeException | IntegrityScanException | RuntimeException exception) {
                    if (prepared != null) {
                        prepared.frames().forEach(ClientHandshakeEngine.OutboundFrame::clear);
                    }
                    if (authenticationAttempts.isActive(attempt)
                            && observationSchedule.isActive(attempt)
                            && handshake == candidate) {
                        observationSchedule.fail(attempt);
                    }
                    if (cancellation.cancelled()) {
                        LOGGER.debug("MCAce cancelled a superseded artifact observation read");
                    } else {
                        LOGGER.warn("MCAce retained a dirty optional artifact observation after scan failed: {}",
                                exception.getMessage());
                    }
                    return;
                }
                ClientHandshakeEngine.PreparedArtifactObservationUpdate ready = prepared;
                try {
                    client.execute(() -> {
                        if (!authenticationAttempts.isActive(attempt)
                                || !isConnectionBoundEnabled(candidate, attempt)
                                || handshake != candidate
                                || !observationSchedule.isActive(attempt)
                                || client.getNetworkHandler() == null) {
                            ready.frames().forEach(ClientHandshakeEngine.OutboundFrame::clear);
                            observationSchedule.cancel();
                            pendingArtifactObservationUpdate = null;
                            return;
                        }
                        PendingArtifactObservationUpdate readyPending =
                                new PendingArtifactObservationUpdate(candidate, attempt, ready,
                                        selectedResourcePacks, selectedShaderPacks, loadedMods);
                        pendingArtifactObservationUpdate = readyPending;
                        boolean sent = OrderedMCAceFrameSender.send(ready.frames(),
                                () -> authenticationAttempts.isActive(attempt)
                                        && isConnectionBoundEnabled(candidate, attempt)
                                        && handshake == candidate
                                        && pendingArtifactObservationUpdate == readyPending
                                        && observationSchedule.isActive(attempt)
                                        && client.getNetworkHandler() != null,
                                new FabricFrameSink());
                        if (sent) {
                            observationSchedule.markSent(attempt);
                        } else {
                            observationSchedule.fail(attempt);
                            LOGGER.warn("MCAce retained a dirty artifact observation after transport delivery failed");
                        }
                    });
                } catch (RuntimeException exception) {
                    ready.frames().forEach(ClientHandshakeEngine.OutboundFrame::clear);
                    observationSchedule.fail(attempt);
                    if (!cancellation.cancelled()) {
                        LOGGER.warn("MCAce could not schedule artifact observation delivery; retry remains active: {}",
                                exception.getMessage());
                    }
                }
            });
        } catch (RuntimeException exception) {
            observationSchedule.fail(attempt);
            LOGGER.warn("MCAce could not start artifact observation collection; retry remains active: {}",
                    exception.getMessage());
        }
    }

    private void retryPendingArtifactObservation(
            MinecraftClient client, PendingArtifactObservationUpdate pending) {
        List<ClientHandshakeEngine.OutboundFrame> retryFrames;
        try {
            retryFrames = pending.candidate().retryArtifactObservationUpdate(pending.prepared());
        } catch (EnvelopeException | RuntimeException exception) {
            observationSchedule.fail(pending.attempt());
            LOGGER.warn("MCAce could not prepare an artifact observation retry: {}", exception.getMessage());
            return;
        }
        boolean sent = OrderedMCAceFrameSender.send(retryFrames,
                () -> authenticationAttempts.isActive(pending.attempt())
                        && isConnectionBoundEnabled(pending.candidate(), pending.attempt())
                        && handshake == pending.candidate()
                        && pendingArtifactObservationUpdate == pending
                        && observationSchedule.isActive(pending.attempt())
                        && client.getNetworkHandler() != null,
                new FabricFrameSink());
        if (sent) {
            observationSchedule.markSent(pending.attempt());
            LOGGER.debug("MCAce resent the exact pending artifact observation after a result timeout");
        } else {
            observationSchedule.fail(pending.attempt());
            LOGGER.warn("MCAce retained a pending artifact observation after retry transport failed");
        }
    }

    private static List<String> currentEnabledResourcePackIds(MinecraftClient client) {
        return client.getResourcePackManager().getEnabledIds().stream()
                .map(Object::toString)
                .toList();
    }

    static boolean selectedPackOrderChanged(List<String> current, List<String> previous) {
        return !java.util.Objects.requireNonNull(current, "current")
                .equals(java.util.Objects.requireNonNull(previous, "previous"));
    }

    private static List<String> currentEnabledShaderPackIds() {
        return ShaderPackObservation.currentEnabledShaderPackIds();
    }

    private record ExplicitFileAuthorization(
            ClientHandshakeEngine candidate, long generation, Set<String> files) {
        private ExplicitFileAuthorization {
            files = Set.copyOf(files);
        }
    }

    private record PendingArtifactObservationUpdate(
            ClientHandshakeEngine candidate,
            long attempt,
            ClientHandshakeEngine.PreparedArtifactObservationUpdate prepared,
            List<String> resourcePacks,
            List<String> shaderPacks,
            List<LoadedModObservation> loadedMods) {
        private PendingArtifactObservationUpdate {
            java.util.Objects.requireNonNull(candidate, "candidate");
            java.util.Objects.requireNonNull(prepared, "prepared");
            resourcePacks = List.copyOf(resourcePacks);
            shaderPacks = List.copyOf(shaderPacks);
            loadedMods = List.copyOf(loadedMods);
        }
    }

    private static final class FabricFrameSink implements OrderedMCAceFrameSender.FrameSink {
        @Override
        public boolean canSend(ClientHandshakeEngine.OutboundFrame frame) {
            return switch (frame.channel()) {
                case HANDSHAKE -> ClientPlayNetworking.canSend(MCAcePayload.ID);
                case PAYLOAD -> ClientPlayNetworking.canSend(MCAceTransferPayload.ID);
            };
        }

        @Override
        public void send(ClientHandshakeEngine.OutboundFrame frame) {
            switch (frame.channel()) {
                case HANDSHAKE -> ClientPlayNetworking.send(new MCAcePayload(frame.data()));
                case PAYLOAD -> ClientPlayNetworking.send(new MCAceTransferPayload(frame.data()));
            }
        }
    }

    private record PendingChallenge(byte[] frame, String address, PublicKey pinnedKey, long generation) {
        private PendingChallenge {
            frame = frame.clone();
        }

        @Override
        public byte[] frame() {
            return frame.clone();
        }
    }
}
