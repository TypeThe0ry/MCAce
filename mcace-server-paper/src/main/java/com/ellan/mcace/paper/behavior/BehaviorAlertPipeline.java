package com.ellan.mcace.paper.behavior;

import com.ellan.mcace.cloudclient.CloudRiskEventClient;
import java.util.Objects;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.logging.Logger;
import org.bukkit.entity.Player;

public final class BehaviorAlertPipeline {
    private final BehaviorAlertCorrelator correlator;
    private final CloudRiskEventClient cloudClient;
    private final BiConsumer<Player, BehaviorAlert> localAuthority;
    private final Logger logger;

    public BehaviorAlertPipeline(
            BehaviorAlertCorrelator correlator,
            CloudRiskEventClient cloudClient,
            Logger logger) {
        this.correlator = Objects.requireNonNull(correlator, "correlator");
        this.cloudClient = Objects.requireNonNull(cloudClient, "cloudClient");
        this.localAuthority = (ignoredPlayer, ignoredAlert) -> { };
        this.logger = Objects.requireNonNull(logger, "logger");
    }

    public BehaviorAlertPipeline(
            BehaviorAlertCorrelator correlator,
            CloudRiskEventClient cloudClient,
            BiConsumer<Player, BehaviorAlert> localAuthority,
            Logger logger) {
        this.correlator = correlator;
        this.cloudClient = cloudClient;
        this.localAuthority = Objects.requireNonNull(localAuthority, "localAuthority");
        this.logger = Objects.requireNonNull(logger, "logger");
        if ((correlator == null) != (cloudClient == null)) {
            throw new IllegalArgumentException("cloud correlator and client must be configured together");
        }
    }

    public void accept(Player carrier, BehaviorAlert alert) {
        Objects.requireNonNull(carrier, "carrier");
        Objects.requireNonNull(alert, "alert");
        if (!carrier.getUniqueId().equals(alert.playerId())) {
            throw new IllegalArgumentException("behavior alert carrier does not match player id");
        }
        localAuthority.accept(carrier, alert);
        if (correlator == null) return;
        correlator.accept(alert).ifPresent(event -> {
            if (!cloudClient.submit(event)) {
                logger.warning("MCAce behavior alert queue is full; event dropped for player " + alert.playerId());
            }
        });
    }

    public void remove(UUID playerId) {
        if (correlator != null) correlator.remove(playerId);
    }
}
