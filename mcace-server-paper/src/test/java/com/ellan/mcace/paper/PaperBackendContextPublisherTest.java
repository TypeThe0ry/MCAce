package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.ellan.mcace.core.context.BackendContextCodec;
import com.ellan.mcace.core.context.BackendContextReport;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import com.ellan.mcace.sdk.RiskBand;
import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;
import org.bukkit.GameMode;
import org.bukkit.NamespacedKey;
import org.bukkit.World;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import org.junit.jupiter.api.Test;

final class PaperBackendContextPublisherTest {
    private static final Instant NOW = Instant.parse("2026-08-12T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final UUID PLAYER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    @Test
    void admissionAndPaperOwnedChangesPublishBoundedContextAndRemovalStopsIt() throws Exception {
        List<byte[]> frames = new ArrayList<>();
        World world = proxy(World.class, (method, arguments) -> switch (method) {
            case "getKey" -> NamespacedKey.minecraft("overworld");
            default -> defaultValue(arguments.returnType());
        });
        Player player = proxy(Player.class, (method, arguments) -> switch (method) {
            case "getUniqueId" -> PLAYER_ID;
            case "getWorld" -> world;
            case "getGameMode" -> GameMode.SURVIVAL;
            case "getListeningPluginChannels" -> Set.of(ProtocolConstants.BACKEND_CONTEXT_CHANNEL);
            case "sendPluginMessage" -> {
                frames.add(((byte[]) arguments.values()[2]).clone());
                yield null;
            }
            default -> defaultValue(arguments.returnType());
        });
        Plugin plugin = proxy(Plugin.class,
                (method, arguments) -> defaultValue(arguments.returnType()));
        PaperBackendContextPublisher publisher = new PaperBackendContextPublisher(
                plugin, CLOCK, Logger.getAnonymousLogger());
        PlayerSecuritySnapshot snapshot = new PlayerSecuritySnapshot(
                PLAYER_ID, TrustLevel.VERIFIED, AdmissionStatus.VERIFIED, 0, RiskBand.NORMAL,
                "test", NOW, List.of());

        publisher.accept(player, new PaperAdmissionReceiver.AcceptedAdmission(
                PLAYER_ID, 41L, NOW.plus(Duration.ofSeconds(15)), snapshot));
        publisher.publishGameMode(player, GameMode.CREATIVE);

        assertEquals(2, frames.size());
        BackendContextCodec codec = new BackendContextCodec(CLOCK);
        BackendContextReport initial = codec.decode(frames.get(0));
        BackendContextReport changed = codec.decode(frames.get(1));
        assertEquals(41L, initial.admissionTransportSequence());
        assertEquals("minecraft:overworld", initial.worldId());
        assertEquals("survival", initial.gameMode());
        assertEquals("creative", changed.gameMode());
        assertEquals(initial.reportSequence() + 1L, changed.reportSequence());

        publisher.remove(PLAYER_ID);
        publisher.publishCurrent(player);
        assertEquals(2, frames.size());

    }

    @Test
    void admissionWaitsForClientChannelRegistrationThenPublishesCurrentContext() throws Exception {
        List<byte[]> frames = new ArrayList<>();
        AtomicReference<Set<String>> listeningChannels = new AtomicReference<>(Set.of());
        World world = proxy(World.class, (method, arguments) -> switch (method) {
            case "getKey" -> NamespacedKey.minecraft("overworld");
            default -> defaultValue(arguments.returnType());
        });
        Player player = proxy(Player.class, (method, arguments) -> switch (method) {
            case "getUniqueId" -> PLAYER_ID;
            case "getWorld" -> world;
            case "getGameMode" -> GameMode.SURVIVAL;
            case "getListeningPluginChannels" -> listeningChannels.get();
            case "sendPluginMessage" -> {
                frames.add(((byte[]) arguments.values()[2]).clone());
                yield null;
            }
            default -> defaultValue(arguments.returnType());
        });
        Plugin plugin = proxy(Plugin.class,
                (method, arguments) -> defaultValue(arguments.returnType()));
        PaperBackendContextPublisher publisher = new PaperBackendContextPublisher(
                plugin, CLOCK, Logger.getAnonymousLogger());
        PlayerSecuritySnapshot snapshot = new PlayerSecuritySnapshot(
                PLAYER_ID, TrustLevel.VERIFIED, AdmissionStatus.VERIFIED, 0, RiskBand.NORMAL,
                "test", NOW, List.of());

        publisher.accept(player, new PaperAdmissionReceiver.AcceptedAdmission(
                PLAYER_ID, 73L, NOW.plus(Duration.ofSeconds(15)), snapshot));
        assertEquals(0, frames.size());

        listeningChannels.set(Set.of(ProtocolConstants.BACKEND_CONTEXT_CHANNEL));
        publisher.channelRegistered(player);

        assertEquals(1, frames.size());
        BackendContextReport report = new BackendContextCodec(CLOCK).decode(frames.get(0));
        assertEquals(73L, report.admissionTransportSequence());
        assertEquals("minecraft:overworld", report.worldId());
        assertEquals("survival", report.gameMode());
    }
    private static <T> T proxy(Class<T> type, ProxyInvocation invocation) {
        Object result = Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
                (proxy, method, arguments) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return switch (method.getName()) {
                            case "toString" -> type.getSimpleName() + "Proxy";
                            case "hashCode" -> System.identityHashCode(proxy);
                            case "equals" -> proxy == arguments[0];
                            default -> null;
                        };
                    }
                    return invocation.invoke(method.getName(), new InvocationArguments(
                            method.getReturnType(), arguments == null ? new Object[0] : arguments));
                });
        return type.cast(result);
    }

    private static Object defaultValue(Class<?> type) {
        if (!type.isPrimitive()) return null;
        if (type == boolean.class) return false;
        if (type == byte.class) return (byte) 0;
        if (type == short.class) return (short) 0;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == float.class) return 0F;
        if (type == double.class) return 0D;
        if (type == char.class) return '\0';
        return null;
    }

    @FunctionalInterface
    private interface ProxyInvocation {
        Object invoke(String method, InvocationArguments arguments) throws Throwable;
    }

    private record InvocationArguments(Class<?> returnType, Object[] values) {
    }
}
