package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.federation.FederationRuntimeState;
import com.ellan.mcace.core.federation.FederationRuntimeStatus;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import net.md_5.bungee.api.CommandSender;
import org.junit.jupiter.api.Test;

final class MCAceFederationCommandTest {
    private static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000001");

    @Test
    void permissionOnlineGateAndContentFreeRenderingMatchVelocity() {
        AtomicInteger issues = new AtomicInteger();
        MCAceFederationCommand command = command(issues);
        List<String> messages = new ArrayList<>();
        command.execute(sender(false, messages), new String[] {"issue", "Lucky", "network-b"});
        command.execute(sender(true, messages), new String[] {"issue", "missing", "network-b"});
        assertEquals(0, issues.get());
        command.execute(sender(true, messages), new String[] {"issue", "Lucky", "network-b"});
        assertEquals(1, issues.get());
        command.execute(sender(true, messages), new String[] {"status"});
        command.execute(sender(true, messages), new String[] {"peers"});
        String output = String.join(" ", messages).toLowerCase(java.util.Locale.ROOT);
        assertTrue(output.contains("network-b"));
        assertTrue(output.contains("audit=healthy"));
        assertTrue(output.contains("audit_backlog=0"));
        assertFalse(output.contains("secret-material"));
        assertFalse(output.contains("sha256"));
        assertFalse(output.contains("token"));
        assertFalse(output.contains("key="));
    }

    private static MCAceFederationCommand command(AtomicInteger issues) {
        return new MCAceFederationCommand(new MCAceFederationCommand.Operations() {
            @Override public FederationRuntimeState status() {
                return new FederationRuntimeState(
                        true, true, true, "network-a", 1, 0, 0, 0, 2L, 0L);
            }
            @Override public List<String> peers() { return List.of("network-b"); }
            @Override public FederationRuntimeStatus issue(UUID playerId, String target, String operator) {
                assertEquals(PLAYER, playerId);
                issues.incrementAndGet();
                return FederationRuntimeStatus.CONSENT_ISSUED;
            }
        }, name -> "Lucky".equals(name) ? Optional.of(PLAYER) : Optional.empty());
    }

    private static CommandSender sender(boolean permission, List<String> messages) {
        return (CommandSender) Proxy.newProxyInstance(
                MCAceFederationCommandTest.class.getClassLoader(), new Class<?>[] {CommandSender.class},
                (proxy, method, values) -> {
                    if ("hasPermission".equals(method.getName())) return permission;
                    if (method.getName().startsWith("sendMessage")) messages.add(String.valueOf(values[0]));
                    if (method.getReturnType() == boolean.class) return false;
                    if (method.getReturnType() == int.class) return 0;
                    return null;
                });
    }
}
