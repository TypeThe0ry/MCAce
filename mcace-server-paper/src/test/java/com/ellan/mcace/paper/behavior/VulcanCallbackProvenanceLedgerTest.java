package com.ellan.mcace.paper.behavior;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Proxy;
import java.time.Clock;
import me.frep.vulcan.api.event.VulcanFlagEvent;
import org.bukkit.event.Listener;
import org.bukkit.plugin.Plugin;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;

@ResourceLock(Resources.SYSTEM_PROPERTIES)
final class VulcanCallbackProvenanceLedgerTest {

    @AfterEach
    void clearProperties() {
        System.clearProperty(VulcanCallbackProvenanceLedger.PATH_PROPERTY);
        System.clearProperty(VulcanCallbackProvenanceLedger.ATTEMPT_PROPERTY);
        System.clearProperty(VulcanCallbackProvenanceLedger.CHALLENGE_PROPERTY);
    }

    @Test
    void staysDisabledWhenNoReleaseEvidencePropertiesArePresent() throws Exception {
        try (VulcanCallbackProvenanceLedger ledger = VulcanCallbackProvenanceLedger.open(
                plugin(), plugin(), VulcanFlagEvent.class, new Listener() { }, Clock.systemUTC())) {
            assertFalse(ledger.enabled());
        }
    }

    @Test
    void rejectsPartialReleaseEvidenceConfiguration() {
        System.setProperty(VulcanCallbackProvenanceLedger.ATTEMPT_PROPERTY, "a".repeat(32));
        assertThrows(ReflectiveOperationException.class, () ->
                VulcanCallbackProvenanceLedger.open(
                        plugin(), plugin(), VulcanFlagEvent.class,
                        new Listener() { }, Clock.systemUTC()));
    }

    private static Plugin plugin() {
        return (Plugin) Proxy.newProxyInstance(
                VulcanCallbackProvenanceLedgerTest.class.getClassLoader(),
                new Class<?>[] {Plugin.class},
                (ignored, method, arguments) -> {
                    Class<?> type = method.getReturnType();
                    if (type == boolean.class) return false;
                    if (type == byte.class) return (byte) 0;
                    if (type == short.class) return (short) 0;
                    if (type == int.class) return 0;
                    if (type == long.class) return 0L;
                    if (type == float.class) return 0.0F;
                    if (type == double.class) return 0.0D;
                    if (type == char.class) return '\0';
                    return null;
                });
    }
}
