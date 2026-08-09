package com.ellan.mcace.paper;

import com.ellan.mcace.core.admission.SignedAdmissionSnapshotCodec;
import com.ellan.mcace.core.admission.SignedAdmissionSnapshotCodec.VerifiedAdmissionSnapshot;
import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bukkit.entity.Player;
import org.bukkit.plugin.messaging.PluginMessageListener;
import org.jetbrains.annotations.NotNull;

final class PaperAdmissionReceiver implements PluginMessageListener {
    private final InMemoryMCAceApi api;
    private final PublicKey proxyPublicKey;
    private final Clock clock;
    private final Logger logger;
    private final SignedAdmissionSnapshotCodec codec;
    private final NonceReplayGuard replayGuard;
    private final MCAceRuntimeScheduler scheduler;
    private final AdmissionObserver observer;
    private final Map<UUID, AcceptedState> accepted = new HashMap<>();

    PaperAdmissionReceiver(
            InMemoryMCAceApi api,
            PublicKey proxyPublicKey,
            Clock clock,
            Logger logger) {
        this(api, proxyPublicKey, clock, logger, null, AdmissionObserver.noop());
    }

    PaperAdmissionReceiver(
            InMemoryMCAceApi api,
            PublicKey proxyPublicKey,
            Clock clock,
            Logger logger,
            MCAceRuntimeScheduler scheduler) {
        this(api, proxyPublicKey, clock, logger, scheduler, AdmissionObserver.noop());
    }

    PaperAdmissionReceiver(
            InMemoryMCAceApi api,
            PublicKey proxyPublicKey,
            Clock clock,
            Logger logger,
            MCAceRuntimeScheduler scheduler,
            AdmissionObserver observer) {
        this.api = Objects.requireNonNull(api, "api");
        this.proxyPublicKey = Objects.requireNonNull(proxyPublicKey, "proxyPublicKey");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.logger = Objects.requireNonNull(logger, "logger");
        this.codec = new SignedAdmissionSnapshotCodec(clock, new SecureRandom());
        this.replayGuard = new NonceReplayGuard(clock, ProtocolConstants.DEFAULT_REPLAY_WINDOW);
        this.scheduler = scheduler;
        this.observer = Objects.requireNonNull(observer, "observer");
    }

    @Override
    public void onPluginMessageReceived(
            @NotNull String channel,
            @NotNull Player player,
            byte @NotNull [] message) {
        if (!ProtocolConstants.ADMISSION_CHANNEL.equals(channel)) {
            return;
        }
        // Plugin messages originate from the connected player transport.  Do not clone or enqueue
        // an oversized untrusted frame before the signed-envelope verifier has a chance to reject it.
        // This is the shared lowest-common proxy budget, so a valid proxy admission snapshot always
        // remains representable while arbitrary client/backend input is bounded at this boundary.
        if (message.length == 0 || message.length > ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES) {
            logger.log(Level.WARNING, "Ignored oversized or empty MCAce admission plugin message");
            return;
        }
        UUID playerId = player.getUniqueId();
        byte[] encoded = message.clone();
        if (scheduler == null) {
            receive(playerId, encoded);
            return;
        }
        scheduler.executeForPlayer(player, () -> receiveAndNotify(player, encoded), () -> remove(playerId));
    }

    synchronized boolean receive(UUID carrierPlayerId, byte[] encoded) {
        return receiveAccepted(carrierPlayerId, encoded).isPresent();
    }

    private void receiveAndNotify(Player carrier, byte[] encoded) {
        receiveAccepted(carrier.getUniqueId(), encoded).ifPresent(update -> observer.accept(carrier, update));
    }

    private synchronized Optional<AcceptedAdmission> receiveAccepted(UUID carrierPlayerId, byte[] encoded) {
        Objects.requireNonNull(carrierPlayerId, "carrierPlayerId");
        Objects.requireNonNull(encoded, "encoded");
        try {
            VerifiedAdmissionSnapshot verified = codec.verify(
                    encoded, carrierPlayerId, proxyPublicKey, replayGuard);
            AcceptedState previous = accepted.get(carrierPlayerId);
            if (previous != null
                    && (verified.transportSequence() <= previous.transportSequence()
                    || verified.snapshot().evaluatedAt().isBefore(previous.evaluatedAt()))) {
                throw new EnvelopeException("stale backend admission update");
            }
            AcceptedState state = new AcceptedState(
                    verified.transportSequence(),
                    verified.snapshot().evaluatedAt(),
                    verified.expiresAt(),
                    verified.snapshot().admissionStatus(),
                    verified.snapshot().trustLevel(),
                    verified.snapshot().riskScore());
            accepted.put(carrierPlayerId, state);
            api.publish(verified.snapshot());
            boolean stateChanged = previous == null
                    || !previous.evaluatedAt().equals(verified.snapshot().evaluatedAt())
                    || previous.admissionStatus() != verified.snapshot().admissionStatus()
                    || previous.trustLevel() != verified.snapshot().trustLevel()
                    || previous.riskScore() != verified.snapshot().riskScore();
            logger.log(stateChanged ? Level.INFO : Level.FINE,
                    "Accepted signed MCAce admission state for {0}: admission={1}, trust={2}, risk={3}",
                    new Object[] {
                        carrierPlayerId,
                        verified.snapshot().admissionStatus(),
                        verified.snapshot().trustLevel(),
                        verified.snapshot().riskScore()
                    });
            return Optional.of(new AcceptedAdmission(
                    carrierPlayerId, state.transportSequence(), state.expiresAt(), verified.snapshot()));
        } catch (EnvelopeException | RuntimeException exception) {
            logger.log(Level.WARNING,
                    "Ignored invalid MCAce admission update for " + carrierPlayerId
                            + "; existing status was not changed",
                    exception);
            return Optional.empty();
        }
    }

    synchronized void expire() {
        Iterator<Map.Entry<UUID, AcceptedState>> iterator = accepted.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<UUID, AcceptedState> entry = iterator.next();
            if (!clock.instant().isBefore(entry.getValue().expiresAt())) {
                api.remove(entry.getKey());
                iterator.remove();
                observer.remove(entry.getKey());
                logger.log(Level.INFO, "Expired signed MCAce admission state for {0}", entry.getKey());
            }
        }
    }

    synchronized void remove(UUID playerId) {
        api.remove(Objects.requireNonNull(playerId, "playerId"));
        accepted.remove(playerId);
        observer.remove(playerId);
    }

    record AcceptedAdmission(
            UUID playerId, long transportSequence, java.time.Instant expiresAt,
            com.ellan.mcace.sdk.PlayerSecuritySnapshot snapshot) {
        AcceptedAdmission {
            Objects.requireNonNull(playerId, "playerId");
            Objects.requireNonNull(expiresAt, "expiresAt");
            Objects.requireNonNull(snapshot, "snapshot");
        }
    }

    interface AdmissionObserver {
        void accept(Player carrier, AcceptedAdmission update);
        void remove(UUID playerId);

        static AdmissionObserver noop() {
            return new AdmissionObserver() {
                @Override public void accept(Player carrier, AcceptedAdmission update) { }
                @Override public void remove(UUID playerId) { }
            };
        }
    }

    private record AcceptedState(
            long transportSequence,
            java.time.Instant evaluatedAt,
            java.time.Instant expiresAt,
            AdmissionStatus admissionStatus,
            TrustLevel trustLevel,
            int riskScore) {
        private AcceptedState {
            Objects.requireNonNull(evaluatedAt, "evaluatedAt");
            Objects.requireNonNull(expiresAt, "expiresAt");
            Objects.requireNonNull(admissionStatus, "admissionStatus");
            Objects.requireNonNull(trustLevel, "trustLevel");
        }
    }
}
