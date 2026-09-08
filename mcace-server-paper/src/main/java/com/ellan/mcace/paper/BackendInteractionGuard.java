package com.ellan.mcace.paper;

import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.bukkit.entity.Player;
import org.bukkit.entity.Projectile;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryDragEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;

/** Opt-in interaction restriction, not a movement barrier or a substitute for a waiting backend. */
final class BackendInteractionGuard implements Listener {
    private final boolean enabled;
    private final Clock clock;
    private final Map<UUID, Permit> permits = new ConcurrentHashMap<>();

    BackendInteractionGuard(boolean enabled, Clock clock) {
        this.enabled = enabled;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    // Called only from the admission receiver's verified-signature observer.
    void accept(Player carrier, PaperAdmissionReceiver.AcceptedAdmission update) {
        if (!enabled || !carrier.isOnline() || !carrier.getUniqueId().equals(update.playerId())) return;
        if (update.snapshot().admissionStatus() != AdmissionStatus.VERIFIED
                || update.snapshot().trustLevel() != TrustLevel.VERIFIED
                || !clock.instant().isBefore(update.expiresAt())) {
            permits.remove(update.playerId());
            return;
        }
        permits.put(update.playerId(), new Permit(carrier, update.expiresAt()));
    }

    boolean restricted(Player player) {
        if (!enabled) return false;
        Permit permit = permits.get(player.getUniqueId());
        if (permit == null || permit.carrier() != player) return true;
        if (!clock.instant().isBefore(permit.expiresAt())) {
            permits.remove(player.getUniqueId(), permit);
            return true;
        }
        return !player.isOnline();
    }

    void remove(UUID playerId) { permits.remove(playerId); }
    void clear() { permits.clear(); }

    @EventHandler public void onJoin(PlayerJoinEvent event) { remove(event.getPlayer().getUniqueId()); }
    @EventHandler public void onQuit(PlayerQuitEvent event) { remove(event.getPlayer().getUniqueId()); }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onBreak(BlockBreakEvent event) {
        if (restricted(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onPlace(BlockPlaceEvent event) {
        if (restricted(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInteract(PlayerInteractEvent event) {
        if (restricted(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onEntityInteract(PlayerInteractEntityEvent event) {
        if (restricted(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onDrop(PlayerDropItemEvent event) {
        if (restricted(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onPickup(EntityPickupItemEvent event) {
        if (event.getEntity() instanceof Player player && restricted(player)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInventoryClick(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof Player player && restricted(player)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onInventoryDrag(InventoryDragEvent event) {
        if (event.getWhoClicked() instanceof Player player && restricted(player)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onAttack(EntityDamageByEntityEvent event) {
        Player attacker = event.getDamager() instanceof Player player ? player
                : event.getDamager() instanceof Projectile projectile
                    && projectile.getShooter() instanceof Player shooter ? shooter : null;
        if (attacker != null && restricted(attacker)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        String command = event.getMessage().strip().split("\\s+", 2)[0];
        if (restricted(event.getPlayer()) && !command.equalsIgnoreCase("/mcace")
                && !command.equalsIgnoreCase("/mcace:mcace")) event.setCancelled(true);
    }

    private record Permit(Player carrier, Instant expiresAt) { }
}
