package com.ellan.mcace.runtime.observer;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.plugin.Plugin;
import org.slf4j.Logger;

/** Test-only, content-free lifecycle barrier for the real reconnect harness. */
@Plugin(
        id = "mcace-runtime-disconnect-observer",
        name = "MCAce Runtime Disconnect Observer",
        version = "1",
        description = "Test-only content-free disconnect lifecycle marker")
public final class VelocityDisconnectObserverPlugin {
    public static final String READY_MARKER = "MCACE_RUNTIME_OBSERVER_READY";
    public static final String DISCONNECT_LAST_LISTENER_OBSERVED_MARKER =
            "MCACE_RUNTIME_OBSERVER_DISCONNECT_LAST_LISTENER_OBSERVED";

    private final Logger logger;

    @Inject
    public VelocityDisconnectObserverPlugin(Logger logger) {
        this.logger = logger;
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        logger.info(READY_MARKER);
    }

    // Velocity 3.5.1 maps the legacy PostOrder.LAST value to priority -32767.
    @Subscribe(priority = -32767)
    public void onDisconnect(DisconnectEvent event) {
        // Never include the event, player, UUID, connection, or disconnect reason.
        logger.info(DISCONNECT_LAST_LISTENER_OBSERVED_MARKER);
    }
}
