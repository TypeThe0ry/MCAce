package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import com.ellan.mcace.sdk.RiskBand;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bukkit.entity.Player;
import org.junit.jupiter.api.Test;

final class BackendLocalSessionActionAdapterTest {
    @Test
    void monitorModeNeverMessagesOrKicksEvenForBlockedState() {
        Probe probe = new Probe(UUID.randomUUID());
        BackendLocalSessionActionAdapter adapter = new BackendLocalSessionActionAdapter(
                BackendSessionActionConfiguration.monitor(), quietLogger());

        adapter.accept(probe.player(), update(probe.playerId, 1, AdmissionStatus.LIMITED));
        adapter.accept(probe.player(), update(probe.playerId, 2, AdmissionStatus.BLOCKED));

        assertEquals(0, probe.messages);
        assertEquals(0, probe.kicks);
    }

    @Test
    void sessionActionsAreBoundedIdempotentAndClearOnRecoveryOrRemoval() {
        Probe probe = new Probe(UUID.randomUUID());
        BackendLocalSessionActionAdapter adapter = new BackendLocalSessionActionAdapter(
                new BackendSessionActionConfiguration(
                        BackendSessionActionConfiguration.Mode.SESSION_ACTIONS, "Limited for this session."),
                quietLogger());

        adapter.accept(probe.player(), update(probe.playerId, 4, AdmissionStatus.LIMITED));
        adapter.accept(probe.player(), update(probe.playerId, 4, AdmissionStatus.LIMITED));
        adapter.accept(probe.player(), update(probe.playerId, 5, AdmissionStatus.LIMITED));
        assertEquals(1, probe.messages);

        adapter.accept(probe.player(), update(probe.playerId, 6, AdmissionStatus.VERIFIED));
        adapter.accept(probe.player(), update(probe.playerId, 7, AdmissionStatus.LIMITED));
        assertEquals(2, probe.messages, "recovery makes a later LIMITED state a new current-session transition");

        adapter.remove(probe.playerId);
        adapter.accept(probe.player(), update(probe.playerId, 7, AdmissionStatus.LIMITED));
        assertEquals(3, probe.messages, "expiry/quit cleanup removes only local idempotency state");
    }

    @Test
    void blockedEndsOnlyTheCurrentCarrierConnection() {
        Probe carrier = new Probe(UUID.randomUUID());
        Probe other = new Probe(UUID.randomUUID());
        BackendLocalSessionActionAdapter adapter = new BackendLocalSessionActionAdapter(
                new BackendSessionActionConfiguration(
                        BackendSessionActionConfiguration.Mode.SESSION_ACTIONS, "Limited for this session."),
                quietLogger());

        adapter.accept(other.player(), update(carrier.playerId, 1, AdmissionStatus.BLOCKED));
        adapter.accept(carrier.player(), update(carrier.playerId, 1, AdmissionStatus.BLOCKED));
        adapter.accept(carrier.player(), update(carrier.playerId, 1, AdmissionStatus.BLOCKED));

        assertEquals(0, other.kicks);
        assertEquals(1, carrier.kicks);
    }

    private static PaperAdmissionReceiver.AcceptedAdmission update(
            UUID playerId, long sequence, AdmissionStatus status) {
        Instant now = Instant.parse("2026-08-09T00:00:00Z");
        return new PaperAdmissionReceiver.AcceptedAdmission(playerId, sequence, now.plusSeconds(30),
                new PlayerSecuritySnapshot(playerId,
                        status == AdmissionStatus.VERIFIED ? TrustLevel.VERIFIED : TrustLevel.UNKNOWN,
                        status, 0, RiskBand.NORMAL, "test", now, List.of()));
    }

    private static Logger quietLogger() {
        Logger logger = Logger.getAnonymousLogger();
        logger.setLevel(Level.OFF);
        return logger;
    }

    private static final class Probe {
        private final UUID playerId;
        private int messages;
        private int kicks;

        private Probe(UUID playerId) {
            this.playerId = playerId;
        }

        private Player player() {
            return (Player) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {Player.class},
                    (ignored, method, arguments) -> switch (method.getName()) {
                        case "getUniqueId" -> playerId;
                        case "isOnline" -> true;
                        case "sendMessage" -> { messages++; yield null; }
                        case "kick" -> { kicks++; yield true; }
                        case "toString" -> "backend-session-probe";
                        default -> defaultValue(method.getReturnType());
                    });
        }

        private static Object defaultValue(Class<?> type) {
            if (!type.isPrimitive()) return null;
            if (type == boolean.class) return false;
            if (type == char.class) return '\0';
            if (type == byte.class) return (byte) 0;
            if (type == short.class) return (short) 0;
            if (type == int.class) return 0;
            if (type == long.class) return 0L;
            if (type == float.class) return 0F;
            if (type == double.class) return 0D;
            throw new IllegalArgumentException("unknown primitive " + type);
        }
    }
}
