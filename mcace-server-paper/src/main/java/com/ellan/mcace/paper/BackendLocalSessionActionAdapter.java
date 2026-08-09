package com.ellan.mcace.paper;

import com.ellan.mcace.sdk.AdmissionStatus;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.kyori.adventure.text.Component;
import org.bukkit.entity.Player;

/**
 * Applies only reversible actions to the current backend connection after the admission receiver
 * has verified proxy signature, replay protection, carrier binding and freshness.
 */
final class BackendLocalSessionActionAdapter {
    private final BackendSessionActionConfiguration configuration;
    private final Logger logger;
    private final Map<UUID, AppliedState> appliedStates = new HashMap<>();

    BackendLocalSessionActionAdapter(BackendSessionActionConfiguration configuration, Logger logger) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.logger = Objects.requireNonNull(logger, "logger");
    }

    synchronized void accept(Player carrier, PaperAdmissionReceiver.AcceptedAdmission update) {
        Objects.requireNonNull(carrier, "carrier");
        Objects.requireNonNull(update, "update");
        if (!carrier.getUniqueId().equals(update.playerId()) || !carrier.isOnline()) {
            return;
        }
        AppliedState prior = appliedStates.get(update.playerId());
        if (prior != null && update.transportSequence() <= prior.transportSequence()) {
            return;
        }
        AdmissionStatus status = update.snapshot().admissionStatus();
        if (status == AdmissionStatus.VERIFIED || status == AdmissionStatus.CONNECTING
                || status == AdmissionStatus.VERIFYING) {
            appliedStates.remove(update.playerId());
            return;
        }
        if (configuration.mode() != BackendSessionActionConfiguration.Mode.SESSION_ACTIONS) {
            return;
        }
        if (prior != null && prior.status() == status) {
            appliedStates.put(update.playerId(), new AppliedState(update.transportSequence(), status));
            return;
        }
        appliedStates.put(update.playerId(), new AppliedState(update.transportSequence(), status));
        if (status == AdmissionStatus.LIMITED) {
            carrier.sendMessage(configuration.limitedMessage());
            return;
        }
        if (status == AdmissionStatus.BLOCKED) {
            carrier.kick(Component.text("MCAce: this connection is blocked. Please reconnect or contact staff."));
            logger.log(Level.INFO, "MCAce ended the current blocked backend session for {0}", update.playerId());
        }
    }

    synchronized void remove(UUID playerId) {
        appliedStates.remove(Objects.requireNonNull(playerId, "playerId"));
    }

    synchronized void clear() {
        appliedStates.clear();
    }

    private record AppliedState(long transportSequence, AdmissionStatus status) { }
}
