package com.ellan.mcace.runtime.observer;

import com.ellan.mcace.sdk.MCAceApi;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import net.kyori.adventure.text.Component;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.java.JavaPlugin;

/**
 * Test-only, content-free observer for the real Paper/Folia admission boundary.
 *
 * <p>After MCAce has installed a verified admission snapshot, this companion schedules one
 * harmless empty action-bar send on the carrier player's entity scheduler and emits one fixed
 * marker. It never reads or logs a UUID, session, key, hash, policy value, or frame.</p>
 */
public final class PaperAdmissionActionObserverPlugin extends JavaPlugin implements Listener {
    public static final String ACTION_MARKER =
            "MCACE_RUNTIME_OBSERVER_LOCAL_ADMISSION_ACTION_EXECUTED";

    private final Map<UUID, Instant> observed = new ConcurrentHashMap<>();
    private MCAceApi api;

    @Override
    public void onEnable() {
        api = Objects.requireNonNull(
                getServer().getServicesManager().load(MCAceApi.class),
                "MCAce SDK service unavailable");
        getServer().getPluginManager().registerEvents(this, this);
        getServer().getGlobalRegionScheduler().runAtFixedRate(
                this, ignored -> observeOnlinePlayers(), 1L, 1L);
        getLogger().info("MCACE_RUNTIME_OBSERVER_READY");
    }

    private void observeOnlinePlayers() {
        for (Player player : getServer().getOnlinePlayers()) {
            UUID playerId = player.getUniqueId();
            api.snapshot(playerId).ifPresent(snapshot -> {
                Instant evaluatedAt = snapshot.evaluatedAt();
                if (evaluatedAt.equals(observed.get(playerId))) {
                    return;
                }
                observed.put(playerId, evaluatedAt);
                boolean scheduled = player.getScheduler().execute(
                        this,
                        () -> executeLocalAction(player, playerId, evaluatedAt),
                        () -> observed.remove(playerId, evaluatedAt),
                        1L);
                if (!scheduled) {
                    observed.remove(playerId, evaluatedAt);
                }
            });
        }
    }

    private void executeLocalAction(Player player, UUID playerId, Instant evaluatedAt) {
        boolean stillAccepted = player.isOnline()
                && api.snapshot(playerId)
                        .map(snapshot -> evaluatedAt.equals(snapshot.evaluatedAt()))
                        .orElse(false);
        if (!stillAccepted) {
            observed.remove(playerId, evaluatedAt);
            return;
        }
        player.sendActionBar(Component.empty());
        getLogger().info(ACTION_MARKER);
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        observed.remove(event.getPlayer().getUniqueId());
    }

    @Override
    public void onDisable() {
        observed.clear();
    }
}
