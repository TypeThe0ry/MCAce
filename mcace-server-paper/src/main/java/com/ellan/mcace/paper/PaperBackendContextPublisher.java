package com.ellan.mcace.paper;

import com.ellan.mcace.core.context.BackendContextCodec;
import com.ellan.mcace.core.context.BackendContextException;
import com.ellan.mcace.core.context.BackendContextReport;
import com.ellan.mcace.protocol.ProtocolConstants;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bukkit.GameMode;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;

/** Publishes Paper/Folia-owned world and game-mode facts for proxy-side shadow comparison. */
final class PaperBackendContextPublisher {

    private final Plugin plugin;
    private final Clock clock;
    private final Logger logger;
    private final BackendContextCodec codec;
    private final AtomicLong reportSequence;
    private final Map<UUID, AdmissionBinding> admissions = new HashMap<>();

    PaperBackendContextPublisher(Plugin plugin, Clock clock, Logger logger) {
        this.plugin = Objects.requireNonNull(plugin, "plugin");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.logger = Objects.requireNonNull(logger, "logger");
        this.codec = new BackendContextCodec(clock);
        this.reportSequence = new AtomicLong(Math.max(1L, clock.millis()));
    }

    void accept(Player player, PaperAdmissionReceiver.AcceptedAdmission admission) {
        Objects.requireNonNull(player, "player");
        Objects.requireNonNull(admission, "admission");
        UUID playerId = player.getUniqueId();
        if (!playerId.equals(admission.playerId())) {
            return;
        }
        synchronized (this) {
            admissions.put(playerId, new AdmissionBinding(
                    admission.transportSequence(), admission.expiresAt()));
        }
        publish(player, player.getGameMode());
    }

    void channelRegistered(Player player) {
        Objects.requireNonNull(player, "player");
        logger.log(Level.FINE, "MCAce backend context transport ready for {0} (shadow-only)",
                player.getUniqueId());
        publishCurrent(player);
    }

    void publishCurrent(Player player) {
        Objects.requireNonNull(player, "player");
        publish(player, player.getGameMode());
    }

    void publishGameMode(Player player, GameMode gameMode) {
        Objects.requireNonNull(player, "player");
        publish(player, Objects.requireNonNull(gameMode, "gameMode"));
    }

    synchronized void remove(UUID playerId) {
        admissions.remove(Objects.requireNonNull(playerId, "playerId"));
    }

    private void publish(Player player, GameMode gameMode) {
        UUID playerId = player.getUniqueId();
        AdmissionBinding admission;
        synchronized (this) {
            admission = admissions.get(playerId);
            if (admission == null) {
                return;
            }
            if (!clock.instant().isBefore(admission.expiresAt())) {
                admissions.remove(playerId);
                return;
            }
        }
        if (!player.getListeningPluginChannels().contains(ProtocolConstants.BACKEND_CONTEXT_CHANNEL)) {
            logger.log(Level.FINE,
                    "MCAce backend context transport deferred for {0}: channel is not registered",
                    playerId);
            return;
        }
        try {
            BackendContextReport report = new BackendContextReport(
                    playerId,
                    admission.transportSequence(),
                    nextReportSequence(),
                    player.getWorld().getKey().toString(),
                    gameMode.name().toLowerCase(Locale.ROOT),
                    clock.instant());
            player.sendPluginMessage(plugin, ProtocolConstants.BACKEND_CONTEXT_CHANNEL, codec.encode(report));
            logger.log(Level.FINE,
                    "Published MCAce shadow backend context for {0}: world={1}, gameMode={2}",
                    new Object[] {playerId, report.worldId(), report.gameMode()});
            logger.log(Level.FINE, "MCAce backend context transport published for {0} (shadow-only)",
                    playerId);
        } catch (BackendContextException | RuntimeException exception) {
            logger.log(Level.WARNING,
                    "Could not publish MCAce shadow backend context for " + playerId
                            + "; admission and player state were not changed",
                    exception);
        }
    }

    private long nextReportSequence() {
        return reportSequence.updateAndGet(
                previous -> Math.max(Math.incrementExact(previous), Math.max(1L, clock.millis())));
    }

    private record AdmissionBinding(long transportSequence, Instant expiresAt) {
        private AdmissionBinding {
            if (transportSequence <= 0L) {
                throw new IllegalArgumentException("transportSequence must be positive");
            }
            Objects.requireNonNull(expiresAt, "expiresAt");
        }
    }
}
