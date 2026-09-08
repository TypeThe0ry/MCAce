package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.*;
import com.ellan.mcace.core.proxy.ArtifactObservationAuditSink;
import com.ellan.mcace.core.proxy.ArtifactTelemetryQuery;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import java.lang.reflect.Proxy;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class MCAceObservationCommandTest {
    @Test void permissionIsCheckedBeforeFreshnessLookup() {
        AtomicInteger calls = new AtomicInteger();
        var command = new MCAceObservationCommand(ArtifactObservationAuditSink.noop(),
                new ArtifactTelemetryQuery((id, age) -> { calls.incrementAndGet(); return Optional.empty(); }),
                new com.ellan.mcace.core.proxy.InventoryTelemetryQuery((id, age) -> { calls.incrementAndGet(); return Optional.empty(); }));
        String[] args = {"freshness", UUID.randomUUID().toString()};
        command.execute(invocation(args, false));
        assertEquals(0, calls.get());
        command.execute(invocation(args, true));
        assertEquals(1, calls.get());
        command.execute(invocation(new String[] {"freshness", "invalid"}, true));
        assertEquals(1, calls.get());
        command.execute(invocation(new String[] {"inventory", args[1]}, false));
        assertEquals(1, calls.get());
        command.execute(invocation(new String[] {"inventory", args[1]}, true));
        assertEquals(2, calls.get());
        command.execute(invocation(new String[] {"inventory", "invalid"}, true));
        assertEquals(2, calls.get());
    }

    private static SimpleCommand.Invocation invocation(String[] args, boolean allowed) {
        CommandSource source = (CommandSource) Proxy.newProxyInstance(
                MCAceObservationCommandTest.class.getClassLoader(), new Class<?>[] {CommandSource.class},
                (proxy, method, values) -> "hasPermission".equals(method.getName())
                        ? allowed && "mcace.admin.audit".equals(values[0]) : null);
        return (SimpleCommand.Invocation) Proxy.newProxyInstance(
                MCAceObservationCommandTest.class.getClassLoader(), new Class<?>[] {SimpleCommand.Invocation.class},
                (proxy, method, values) -> "arguments".equals(method.getName()) ? args : source);
    }
}
