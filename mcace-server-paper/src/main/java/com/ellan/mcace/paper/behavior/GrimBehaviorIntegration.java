package com.ellan.mcace.paper.behavior;

import ac.grim.grimac.api.GrimAPIProvider;
import ac.grim.grimac.api.GrimAbstractAPI;
import ac.grim.grimac.api.event.events.FlagEvent;
import ac.grim.grimac.api.plugin.GrimPlugin;
import java.time.Clock;
import java.util.Objects;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;

public final class GrimBehaviorIntegration implements AutoCloseable {
    private static final int MONITOR_PRIORITY = 100;

    private final GrimAbstractAPI api;
    private final GrimPlugin owner;
    private final String providerVersion;

    public GrimBehaviorIntegration(Plugin plugin, BehaviorAlertPipeline pipeline, Clock clock) {
        Objects.requireNonNull(plugin, "plugin");
        Objects.requireNonNull(pipeline, "pipeline");
        Objects.requireNonNull(clock, "clock");
        this.api = GrimAPIProvider.get();
        this.owner = api.getGrimPlugin(plugin);
        this.providerVersion = exact(api.getGrimVersion(), 32);
        FlagEvent.Channel channel = api.getEventBus().get(FlagEvent.class);
        channel.onFlagSupplier(owner, (user, check, verbose, cancelled) -> {
            if (!cancelled) {
                try {
                    Player carrier = plugin.getServer().getPlayer(user.getUniqueId());
                    // Preserve the exact Bukkit Player capability for the whole callback.  A
                    // delayed Grim callback from a retired physical login must not be rebound by
                    // UUID to a newer Player object for the same account.
                    if (carrier != null && api.getGrimUser(user.getUniqueId()) == user) {
                        String checkName = exact(check.getCheckName(), 64);
                        String stableCheck = exact(check.getStableKey(), 96);
                        double violationLevel = Math.max(0.0D, check.getViolations());
                        boolean experimental = check.isExperimental();
                        String providerEventId = BehaviorAlert.providerEventIdSha256(
                                "grim", user.getUniqueId().toString(), providerVersion,
                                stableCheck, checkName, Double.toHexString(violationLevel),
                                Boolean.toString(experimental), String.valueOf(verbose));
                        pipeline.accept(carrier, new BehaviorAlert(
                                user.getUniqueId(), providerEventId, "grim", providerVersion,
                                checkName, stableCheck, violationLevel, experimental,
                                clock.instant()));
                    }
                } catch (IllegalArgumentException ignored) {
                    // An unrepresentable provider/check identity is rejected rather than
                    // truncated into an alias accepted by the frozen authority profile.
                }
            }
            return cancelled;
        }, MONITOR_PRIORITY, false);
    }

    @Override
    public void close() {
        api.getEventBus().unregisterAllListeners(owner);
    }

    private static String exact(String value, int maximum) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Grim provider identity is missing");
        }
        String normalized = value.strip();
        if (normalized.length() > maximum) {
            throw new IllegalArgumentException("Grim provider identity exceeds protocol bounds");
        }
        return normalized;
    }
}
