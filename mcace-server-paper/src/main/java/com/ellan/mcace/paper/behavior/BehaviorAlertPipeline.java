package com.ellan.mcace.paper.behavior;

import com.ellan.mcace.cloudclient.CloudRiskEventClient;
import java.util.Objects;
import java.util.UUID;
import java.util.logging.Logger;

public final class BehaviorAlertPipeline {
    private final BehaviorAlertCorrelator correlator;
    private final CloudRiskEventClient cloudClient;
    private final Logger logger;

    public BehaviorAlertPipeline(
            BehaviorAlertCorrelator correlator,
            CloudRiskEventClient cloudClient,
            Logger logger) {
        this.correlator = Objects.requireNonNull(correlator, "correlator");
        this.cloudClient = Objects.requireNonNull(cloudClient, "cloudClient");
        this.logger = Objects.requireNonNull(logger, "logger");
    }

    public void accept(BehaviorAlert alert) {
        correlator.accept(alert).ifPresent(event -> {
            if (!cloudClient.submit(event)) {
                logger.warning("MCAce behavior alert queue is full; event dropped for player " + alert.playerId());
            }
        });
    }

    public void remove(UUID playerId) {
        correlator.remove(playerId);
    }
}
