package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.*;
import com.ellan.mcace.core.proxy.ArtifactObservationAuditSink;
import com.ellan.mcace.core.proxy.ArtifactTelemetryQuery;
import java.lang.reflect.Proxy;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import net.md_5.bungee.api.CommandSender;
import org.junit.jupiter.api.Test;

final class MCAceObservationCommandTest {
    @Test void permissionIsCheckedBeforeFreshnessLookup() {
        AtomicInteger calls = new AtomicInteger();
        var command = new MCAceObservationCommand(ArtifactObservationAuditSink.noop(),
                new ArtifactTelemetryQuery((id, age) -> { calls.incrementAndGet(); return Optional.empty(); }));
        String[] args = {"freshness", UUID.randomUUID().toString()};
        command.execute(sender(false), args);
        assertEquals(0, calls.get());
        command.execute(sender(true), args);
        assertEquals(1, calls.get());
        command.execute(sender(true), new String[] {"freshness", "invalid"});
        assertEquals(1, calls.get());
    }

    private static CommandSender sender(boolean allowed) {
        return (CommandSender) Proxy.newProxyInstance(MCAceObservationCommandTest.class.getClassLoader(),
                new Class<?>[] {CommandSender.class}, (proxy, method, values) ->
                        "hasPermission".equals(method.getName())
                                ? allowed && "mcace.admin.audit".equals(values[0]) : null);
    }
}
