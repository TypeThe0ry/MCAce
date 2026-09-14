package com.ellan.mcace.paper.behavior;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;
import org.bukkit.entity.Player;
import org.junit.jupiter.api.Test;

final class BehaviorAlertPipelineTest {
    private static final UUID PLAYER_ID =
            UUID.fromString("30000000-0000-4000-8000-000000000001");

    @Test
    void preservesTheExactCarrierCapabilityAndRejectsUuidMismatch() {
        AtomicReference<Player> observedCarrier = new AtomicReference<>();
        AtomicReference<BehaviorAlert> observedAlert = new AtomicReference<>();
        BehaviorAlertPipeline pipeline = new BehaviorAlertPipeline(
                null, null, (carrier, alert) -> {
                    observedCarrier.set(carrier);
                    observedAlert.set(alert);
                }, Logger.getLogger("mcace-behavior-carrier-test"));
        Player carrier = player(PLAYER_ID);
        BehaviorAlert alert = new BehaviorAlert(
                PLAYER_ID, BehaviorAlert.providerEventIdSha256("grim", "pipeline-event-1"),
                "grim", "1.0.0", "timer", "timer-stable",
                1.0D, false, Instant.parse("2026-08-26T00:00:00Z"));

        pipeline.accept(carrier, alert);

        assertSame(carrier, observedCarrier.get());
        assertSame(alert, observedAlert.get());
        Player other = player(UUID.fromString("30000000-0000-4000-8000-000000000002"));
        assertThrows(IllegalArgumentException.class, () -> pipeline.accept(other, alert));
        assertEquals(PLAYER_ID, observedCarrier.get().getUniqueId());
    }

    private static Player player(UUID playerId) {
        return (Player) Proxy.newProxyInstance(
                BehaviorAlertPipelineTest.class.getClassLoader(),
                new Class<?>[] {Player.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "getUniqueId" -> playerId;
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == arguments[0];
                    case "toString" -> "behavior-carrier-" + playerId;
                    default -> primitiveDefault(method.getReturnType());
                });
    }

    private static Object primitiveDefault(Class<?> type) {
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == byte.class) return (byte) 0;
        if (type == short.class) return (short) 0;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == float.class) return 0.0F;
        if (type == double.class) return 0.0D;
        if (type == char.class) return '\0';
        throw new IllegalArgumentException("unsupported primitive " + type);
    }
}
