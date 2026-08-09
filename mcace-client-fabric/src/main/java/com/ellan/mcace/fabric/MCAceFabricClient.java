package com.ellan.mcace.fabric;

import com.ellan.mcace.client.integrity.ClientIntegrityBundle;
import com.ellan.mcace.client.integrity.IntegrityScanException;
import com.ellan.mcace.client.integrity.PolicyDrivenIntegrityCollector;
import com.ellan.mcace.client.observation.ArtifactObservationCollector;
import com.ellan.mcace.client.policy.VerifiedPolicy;
import com.ellan.mcace.client.policy.VerifiedPolicyCache;
import com.ellan.mcace.client.session.ClientHandshakeEngine;
import com.ellan.mcace.client.federation.FederationTokenVault;
import com.ellan.mcace.client.session.ServerKeyPins;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
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
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientLifecycleEvents;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.fabricmc.fabric.api.client.rendering.v1.WorldRenderEvents;
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
    private EvidenceCaptureController evidenceCapture;
    private final FederationTokenVault federationVault = new FederationTokenVault();
    private final FederationConsentController federationConsent = new FederationConsentController(Clock.systemUTC());
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
        PayloadTypeRegistry.playC2S().register(MCAcePayload.ID, MCAcePayload.CODEC);
        PayloadTypeRegistry.playC2S().register(MCAceTransferPayload.ID, MCAceTransferPayload.CODEC);
        ClientPlayNetworking.registerGlobalReceiver(MCAcePayload.ID, this::receivePayload);
        ClientTickEvents.END_CLIENT_TICK.register(client -> {
            resumePendingChallenge(client);
            scheduleHeartbeat(client);
            scheduleArtifactObservation(client);
            evidenceCapture.tick(client);
            pumpEvidenceFrames(client);
            federationConsent.tick(client);
        });
        ClientPlayConnectionEvents.DISCONNECT.register((handler, client) -> cancelAuthentication("disconnect"));
        WorldRenderEvents.END.register(context -> evidenceCapture.captureAtEndOfWorldRender(MinecraftClient.getInstance()));
        ClientLifecycleEvents.CLIENT_STOPPING.register(client -> {
            federationConsent.cancel(client);
            federationVault.close();
            evidenceCapture.close();
        });
        configurePlatformSmokeConnection();
        LOGGER.info("MCAce Fabric client initialized; {} server key pin(s) available",
                serverKeyPins.empty() ? "no" : "configured");
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

    private void receivePayload(MCAcePayload payload, ClientPlayNetworking.Context context) {
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
            receiveAuthResult(payload, context);
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
        cancelQueuedEvidenceFrames();
        evidenceCapture.cancel(context.client());
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
                networkHandler.getProfile().getId(),
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
                networkHandler.getProfile().getId(),
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
        Thread.ofVirtual().name("mcace-policy-integrity-scan").start(() -> {
            try {
                // Never use the payload's provisional serverId to look inside the federation
                // vault. A server can send an arbitrary plugin message before SERVER_HELLO's
                // envelope signature is checked; letting that text select a target would allow
                // it to burn a player-approved grant by naming a different pinned target.
                ClientHandshakeEngine preliminary = new ClientHandshakeEngine(playerId,
                        buildMetadata.clientVersion(), buildMetadata.minecraftVersion(), buildMetadata.buildId(),
                        LoaderType.FABRIC, pinnedKey, Clock.systemUTC(), new SecureRandom());
                VerifiedPolicy policy = preliminary.prepareServerHello(frame, address, policyCache);
                ClientHandshakeEngine candidate = federationVault.newTargetHandshake(
                                preliminary.verifiedServerId(), playerId, buildMetadata.clientVersion(),
                                buildMetadata.minecraftVersion(), buildMetadata.buildId(), LoaderType.FABRIC,
                                pinnedKey, Clock.systemUTC(), new SecureRandom())
                        .orElse(preliminary);
                if (candidate != preliminary) {
                    // Re-verify the same signed hello and policy with the exact, vault-owned
                    // target key. Only this engine may emit the final CLIENT_HELLO.
                    policy = candidate.prepareServerHello(frame, address, policyCache);
                }
                VerifiedPolicy verifiedPolicy = policy;
                ClientIntegrityBundle bundle = new PolicyDrivenIntegrityCollector(Clock.systemUTC())
                        .collect(gameDirectory, verifiedPolicy.policy());
                List<ClientHandshakeEngine.OutboundFrame> responses = candidate.createAuthenticationFrames(
                        bundle,
                        new ArtifactObservationCollector().collect(gameDirectory, verifiedPolicy.policy(), bundle));
                client.execute(() -> {
                    if (!authenticationAttempts.isActive(generation) || client.getNetworkHandler() == null) {
                        LOGGER.info("MCAce discarded a superseded authentication response");
                        return;
                    }
                    handshake = candidate;
                    if (!OrderedMCAceFrameSender.send(
                            responses,
                            () -> authenticationAttempts.isActive(generation)
                                    && client.getNetworkHandler() != null,
                            new FabricFrameSink())) {
                        handshake = null;
                        LOGGER.warn("MCAce stopped authentication frame delivery because the connection changed or a channel was unavailable");
                        return;
                    }
                    LOGGER.info("MCAce answered signed policy {} sequence {} with {} scoped manifests",
                            verifiedPolicy.policy().getPolicyVersion(), verifiedPolicy.policy().getSequence(),
                            bundle.scopes().size());
                });
            } catch (EnvelopeException | IntegrityScanException exception) {
                LOGGER.warn("MCAce rejected the challenge or scoped integrity request: {}", exception.getMessage());
            }
        });
    }

    private void receiveAuthResult(MCAcePayload payload, ClientPlayNetworking.Context context) {
        ClientHandshakeEngine candidate = handshake;
        if (candidate == null) {
            LOGGER.warn("MCAce received an authentication result without an active handshake");
            return;
        }
        try {
            com.ellan.mcace.protocol.generated.AuthResult result = candidate.receiveAuthResult(payload.data());
            if (result.getAccepted()) {
                LOGGER.info("MCAce session verified at trust level {} with risk score {}",
                        result.getTrustLevel(), result.getRiskScore());
                long attempt = authenticationAttempts.activeAttempt();
                if (authenticationAttempts.isActive(attempt) && handshake == candidate && candidate.heartbeatReady()) {
                    heartbeatSchedule.activate(attempt);
                    observationSchedule.activate(attempt);
                    sendFederationPresentation(candidate, context.client(), attempt);
                } else {
                    // A connection transition raced the result. Never let it revive an old session.
                    cancelAuthentication("superseded authentication result");
                }
            } else {
                LOGGER.warn("MCAce authentication was declined: {}", result.getReasonCodesList());
                cancelAuthentication("authentication declined");
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
            cancelAuthentication("invalid authentication result");
        }
    }

    private void receiveFederationConsentRequest(MCAcePayload payload, ClientPlayNetworking.Context context) {
        ClientHandshakeEngine candidate = handshake;
        if (candidate == null) return;
        try {
            ClientHandshakeEngine.VerifiedFederationConsentRequest request =
                    candidate.receiveFederationConsentRequest(payload.data());
            federationConsent.accept(context.client(), request, new FederationConsentController.Sender() {
                @Override public void allowed(ClientHandshakeEngine.VerifiedFederationConsentRequest allowed) {
                    Thread.ofVirtual().name("mcace-federation-consent").start(() -> {
                        try {
                            byte[] response = candidate.createFederationConsentFrame(allowed);
                            context.client().execute(() -> {
                                if (handshake != candidate || context.client().getNetworkHandler() == null
                                        || !ClientPlayNetworking.canSend(MCAcePayload.ID)) {
                                    candidate.cancelFederationConsent(allowed);
                                    return;
                                }
                                try {
                                    ClientPlayNetworking.send(new MCAcePayload(response));
                                } catch (RuntimeException exception) {
                                    candidate.cancelFederationConsent(allowed);
                                }
                            });
                        } catch (EnvelopeException exception) {
                            candidate.cancelFederationConsent(allowed);
                        }
                    });
                }
                @Override public void declined(ClientHandshakeEngine.VerifiedFederationConsentRequest declined) {
                    candidate.cancelFederationConsent(declined);
                }
            });
        } catch (EnvelopeException exception) {
            LOGGER.warn("MCAce rejected a federation consent request: {}", exception.getMessage());
        }
    }

    private void receiveFederationGrant(MCAcePayload payload, ClientPlayNetworking.Context context) {
        ClientHandshakeEngine candidate = handshake;
        if (candidate == null) return;
        try {
            candidate.receiveFederationGrant(payload.data(), federationVault);
            LOGGER.info("MCAce stored a one-time federation grant in memory only");
        } catch (EnvelopeException exception) {
            LOGGER.warn("MCAce rejected a federation grant: {}", exception.getMessage());
        }
    }

    private void sendFederationPresentation(ClientHandshakeEngine candidate, MinecraftClient client, long attempt) {
        Thread.ofVirtual().name("mcace-federation-presentation").start(() -> {
            FederationTokenVault.PreparedPresentation prepared = null;
            try {
                prepared = federationVault.preparePresentation(candidate.authenticatedServerId(),
                        client.getNetworkHandler().getProfile().getId(), candidate.authenticatedSessionId(),
                        candidate.federationChallengeNonce(), Clock.systemUTC()).orElse(null);
                if (prepared == null) return;
                byte[] frame = candidate.createFederationPresentationFrame(prepared.encoded());
                FederationTokenVault.PreparedPresentation reserved = prepared;
                client.execute(() -> {
                    if (!authenticationAttempts.isActive(attempt) || handshake != candidate
                            || client.getNetworkHandler() == null || !ClientPlayNetworking.canSend(MCAcePayload.ID)) {
                        federationVault.sendFailed(reserved);
                        return;
                    }
                    try {
                        ClientPlayNetworking.send(new MCAcePayload(frame));
                        federationVault.commit(reserved);
                    } catch (RuntimeException exception) {
                        federationVault.sendFailed(reserved);
                    }
                });
            } catch (Exception exception) {
                if (prepared != null) federationVault.sendFailed(prepared);
                LOGGER.debug("MCAce federation presentation is unavailable: {}", exception.getMessage());
            }
        });
    }

    private void receiveEvidenceRequest(MCAcePayload payload, ClientPlayNetworking.Context context) {
        ClientHandshakeEngine candidate = handshake;
        if (candidate == null || !candidate.heartbeatReady()) {
            LOGGER.warn("MCAce ignored an evidence request without an authenticated session");
            return;
        }
        try {
            ClientHandshakeEngine.VerifiedEvidenceRequest request = candidate.receiveEvidenceRequest(payload.data());
            long attempt = authenticationAttempts.activeAttempt();
            evidenceCapture.accept(context.client(), request, new EvidenceSender(context.client(), candidate, attempt));
            if (request.captureScope() == com.ellan.mcace.protocol.generated.EvidenceCaptureScope.GAME_RENDER_FRAME) {
                LOGGER.info("MCAce evidence consent screen shown for signed GAME_RENDER_FRAME request id={}",
                        request.requestId());
            }
        } catch (EnvelopeException exception) {
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

    private void cancelAuthentication(String reason) {
        cancelQueuedEvidenceFrames();
        if (evidenceCapture != null) {
            evidenceCapture.cancel(MinecraftClient.getInstance());
        }
        authenticationAttempts.cancel();
        heartbeatSchedule.cancel();
        observationSchedule.cancel();
        pendingChallenge = null;
        handshake = null;
        federationConsent.cancel(MinecraftClient.getInstance());
        LOGGER.debug("MCAce cancelled pending authentication: {}", reason);
    }

    private final class EvidenceSender implements EvidenceCaptureController.Sender {
        private final MinecraftClient client;
        private final ClientHandshakeEngine candidate;
        private final long attempt;

        private EvidenceSender(MinecraftClient client, ClientHandshakeEngine candidate, long attempt) {
            this.client = client;
            this.candidate = candidate;
            this.attempt = attempt;
        }

        @Override
        public void sendOutcome(ClientHandshakeEngine.VerifiedEvidenceRequest request,
                EvidenceCollectionStatus status) {
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
            removeQueuedEvidenceFrames(request);
            candidate.cancelEvidenceRequest(request);
        }

        private void enqueueEvidenceFrames(ClientHandshakeEngine.VerifiedEvidenceRequest request,
                List<ClientHandshakeEngine.OutboundFrame> frames) {
            if (!authenticationAttempts.isActive(attempt) || handshake != candidate) {
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
        if (candidate == null || !candidate.heartbeatReady()) {
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
        if (candidate == null || !candidate.heartbeatReady()) {
            if (observationSchedule.isActive(attempt)) observationSchedule.cancel();
            return;
        }
        if (!observationSchedule.takeDue(attempt)) return;
        Thread.ofVirtual().name("mcace-artifact-observation").start(() -> {
            final ClientHandshakeEngine.PreparedArtifactObservationUpdate prepared;
            try {
                prepared = candidate.prepareRescannedArtifactObservationUpdate(gameDirectory);
            } catch (EnvelopeException | IntegrityScanException | RuntimeException exception) {
                observationSchedule.cancel();
                LOGGER.warn("MCAce stopped optional artifact observation refresh: {}", exception.getMessage());
                return;
            }
            client.execute(() -> {
                if (!authenticationAttempts.isActive(attempt) || handshake != candidate
                        || !observationSchedule.isActive(attempt) || client.getNetworkHandler() == null) {
                    prepared.frames().forEach(ClientHandshakeEngine.OutboundFrame::clear);
                    observationSchedule.cancel();
                    return;
                }
                boolean sent = OrderedMCAceFrameSender.send(prepared.frames(),
                        () -> authenticationAttempts.isActive(attempt) && handshake == candidate
                                && observationSchedule.isActive(attempt) && client.getNetworkHandler() != null,
                        new FabricFrameSink());
                if (sent) {
                    try {
                        candidate.commitArtifactObservationUpdate(prepared);
                        observationSchedule.complete(attempt);
                    } catch (EnvelopeException exception) {
                        observationSchedule.cancel();
                        LOGGER.warn("MCAce discarded an uncommittable artifact observation update: {}", exception.getMessage());
                    }
                } else observationSchedule.cancel();
            });
        });
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
