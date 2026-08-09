package com.ellan.mcace.paper.behavior;

import ac.grim.grimac.api.GrimAPIProvider;
import ac.grim.grimac.api.GrimAbstractAPI;
import ac.grim.grimac.api.event.events.FlagEvent;
import ac.grim.grimac.api.plugin.GrimPlugin;
import java.time.Clock;
import java.util.Objects;
import org.bukkit.plugin.Plugin;

public final class GrimBehaviorIntegration implements AutoCloseable {
    private static final int MONITOR_PRIORITY = 100;

    private final GrimAbstractAPI api;
    private final GrimPlugin owner;

    public GrimBehaviorIntegration(Plugin plugin, BehaviorAlertPipeline pipeline, Clock clock) {
        Objects.requireNonNull(plugin, "plugin");
        Objects.requireNonNull(pipeline, "pipeline");
        Objects.requireNonNull(clock, "clock");
        this.api = GrimAPIProvider.get();
        this.owner = api.getGrimPlugin(plugin);
        FlagEvent.Channel channel = api.getEventBus().get(FlagEvent.class);
        channel.onFlagSupplier(owner, (user, check, verbose, cancelled) -> {
            if (!cancelled) {
                pipeline.accept(new BehaviorAlert(
                        user.getUniqueId(), "grim", bounded(api.getGrimVersion(), 32),
                        bounded(check.getCheckName(), 64), bounded(check.getStableKey(), 96),
                        Math.max(0.0D, check.getViolations()), check.isExperimental(), clock.instant()));
            }
            return cancelled;
        }, MONITOR_PRIORITY, false);
    }

    @Override
    public void close() {
        api.getEventBus().unregisterAllListeners(owner);
    }

    private static String bounded(String value, int maximum) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        String normalized = value.strip();
        return normalized.length() <= maximum ? normalized : normalized.substring(0, maximum);
    }
}
