package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.federation.FederationRuntimeState;
import com.ellan.mcace.core.federation.FederationRuntimeStatus;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class MCAceFederationCommandTest {
    private static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000001");

    @Test
    void permissionAndOnlinePlayerGateIssueWithoutRenderingSensitiveMaterial() {
        AtomicInteger issues = new AtomicInteger();
        MCAceFederationCommand command = command(issues);
        List<String> messages = new ArrayList<>();
        command.execute(invocation(new String[] {"issue", "Lucky", "network-b"}, false, messages));
        assertEquals(0, issues.get());

        command.execute(invocation(new String[] {"issue", "missing", "network-b"}, true, messages));
        assertEquals(0, issues.get());

        command.execute(invocation(new String[] {"issue", "Lucky", "network-b"}, true, messages));
        assertEquals(1, issues.get());
        String output = String.join(" ", messages).toLowerCase(java.util.Locale.ROOT);
        assertFalse(output.contains("secret-material"));
        assertFalse(output.contains("sha256"));
        assertFalse(output.contains("token"));
        assertFalse(output.contains("key="));
    }

    @Test
    void statusAndPeersAreBoundedContentFreeSummaries() {
        MCAceFederationCommand command = command(new AtomicInteger());
        List<String> messages = new ArrayList<>();
        command.execute(invocation(new String[] {"status"}, true, messages));
        command.execute(invocation(new String[] {"peers"}, true, messages));
        String output = String.join(" ", messages);
        assertTrue(output.contains("network-b"));
        assertTrue(output.contains("audit=HEALTHY"));
        assertTrue(output.contains("audit_backlog=0"));
        assertFalse(output.contains("secret-material"));
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
                assertEquals("network-b", target);
                issues.incrementAndGet();
                return FederationRuntimeStatus.CONSENT_ISSUED;
            }
        }, name -> "Lucky".equals(name) ? Optional.of(PLAYER) : Optional.empty());
    }

    private static SimpleCommand.Invocation invocation(
            String[] arguments, boolean permission, List<String> messages) {
        CommandSource source = (CommandSource) Proxy.newProxyInstance(
                MCAceFederationCommandTest.class.getClassLoader(), new Class<?>[] {CommandSource.class},
                (proxy, method, values) -> {
                    if ("hasPermission".equals(method.getName())) return permission;
                    if ("sendMessage".equals(method.getName())) messages.add(String.valueOf(values[0]));
                    if (method.getReturnType() == boolean.class) return false;
                    return null;
                });
        return (SimpleCommand.Invocation) Proxy.newProxyInstance(
                MCAceFederationCommandTest.class.getClassLoader(), new Class<?>[] {SimpleCommand.Invocation.class},
                (proxy, method, values) -> "arguments".equals(method.getName()) ? arguments : source);
    }
}
