package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.*;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import com.ellan.mcace.sdk.RiskBand;
import java.lang.reflect.Proxy;
import java.time.*;
import java.util.List;
import java.util.UUID;
import org.bukkit.block.Block;
import org.bukkit.entity.Player;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.junit.jupiter.api.Test;

final class BackendInteractionGuardTest {
    private static final Instant NOW = Instant.parse("2026-09-08T00:00:00Z");

    @Test void permitRequiresFreshVerifiedStateAndExactConnection() {
        UUID id = UUID.randomUUID();
        Player player = player(id);
        MutableClock clock = new MutableClock();
        BackendInteractionGuard guard = new BackendInteractionGuard(true, clock);
        assertTrue(guard.restricted(player));
        guard.accept(player, update(id, AdmissionStatus.VERIFYING, TrustLevel.UNKNOWN));
        assertTrue(guard.restricted(player));
        guard.accept(player, update(id, AdmissionStatus.VERIFIED, TrustLevel.UNKNOWN));
        assertTrue(guard.restricted(player));
        guard.accept(player, update(id, AdmissionStatus.VERIFIED, TrustLevel.VERIFIED));
        assertFalse(guard.restricted(player));
        assertTrue(guard.restricted(player(id)), "reconnect cannot inherit the old object's permit");
        clock.now = NOW.plusSeconds(15);
        assertTrue(guard.restricted(player), "expiry must be checked without waiting for cleanup polling");
    }

    @Test void revokedRemovedAndWrongCarrierNeverRetainPermission() {
        UUID id = UUID.randomUUID();
        Player player = player(id);
        BackendInteractionGuard guard = new BackendInteractionGuard(true, new MutableClock());
        guard.accept(player, update(UUID.randomUUID(), AdmissionStatus.VERIFIED, TrustLevel.VERIFIED));
        assertTrue(guard.restricted(player));
        guard.accept(player, update(id, AdmissionStatus.VERIFIED, TrustLevel.VERIFIED));
        guard.accept(player, update(id, AdmissionStatus.LIMITED, TrustLevel.UNKNOWN));
        assertTrue(guard.restricted(player));
        guard.accept(player, update(id, AdmissionStatus.VERIFIED, TrustLevel.VERIFIED));
        guard.remove(id);
        assertTrue(guard.restricted(player));
        guard.accept(player, update(id, AdmissionStatus.VERIFIED, TrustLevel.VERIFIED));
        guard.clear();
        assertTrue(guard.restricted(player));
    }

    @Test void eventHandlersRestrictPendingButKeepStatusCommandAvailable() {
        Player player = player(UUID.randomUUID());
        BackendInteractionGuard guard = new BackendInteractionGuard(true, new MutableClock());
        Block block = (Block) Proxy.newProxyInstance(Block.class.getClassLoader(),
                new Class<?>[] {Block.class}, (p, m, a) -> null);
        BlockBreakEvent pending = new BlockBreakEvent(block, player);
        guard.onBreak(pending);
        assertTrue(pending.isCancelled());
        for (String command : List.of("/op someone", "/mcaceevil", "/minecraft:give @s stone")) {
            PlayerCommandPreprocessEvent event = new PlayerCommandPreprocessEvent(player, command, java.util.Set.of());
            guard.onCommand(event);
            assertTrue(event.isCancelled());
        }
        PlayerCommandPreprocessEvent status = new PlayerCommandPreprocessEvent(
                player, "/mcace check test-player", java.util.Set.of());
        guard.onCommand(status);
        assertFalse(status.isCancelled());
        guard.accept(player, update(player.getUniqueId(), AdmissionStatus.VERIFIED, TrustLevel.VERIFIED));
        BlockBreakEvent verified = new BlockBreakEvent(block, player);
        guard.onBreak(verified);
        assertFalse(verified.isCancelled());
    }

    @Test void disabledGuardPreservesMonitorBehavior() {
        assertFalse(new BackendInteractionGuard(false, new MutableClock()).restricted(player(UUID.randomUUID())));
    }

    private static Player player(UUID id) {
        return (Player) Proxy.newProxyInstance(Player.class.getClassLoader(), new Class<?>[] {Player.class},
                (p, m, a) -> switch (m.getName()) {
                    case "getUniqueId" -> id;
                    case "isOnline" -> true;
                    case "hashCode" -> System.identityHashCode(p);
                    case "equals" -> p == a[0];
                    case "toString" -> "test-player";
                    default -> null;
                });
    }

    private static PaperAdmissionReceiver.AcceptedAdmission update(
            UUID id, AdmissionStatus status, TrustLevel trust) {
        return new PaperAdmissionReceiver.AcceptedAdmission(id, 1, NOW.plusSeconds(15),
                new PlayerSecuritySnapshot(id, trust, status, 0, RiskBand.NORMAL, "test", NOW, List.of()));
    }

    private static final class MutableClock extends Clock {
        private Instant now = NOW;
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) throw new IllegalArgumentException("UTC only");
            return this;
        }
        @Override public Instant instant() { return now; }
    }
}
