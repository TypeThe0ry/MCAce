package com.ellan.mcace.paper.behavior;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import org.bukkit.event.Event;
import org.bukkit.event.HandlerList;
import org.bukkit.plugin.Plugin;
import org.junit.jupiter.api.Test;

final class VulcanBehaviorIntegrationTest {
    private static final class ForeignFlagEvent extends Event {
        private static final HandlerList HANDLERS = new HandlerList();

        @Override
        public HandlerList getHandlers() {
            return HANDLERS;
        }
    }

    @Test
    void onlyEventsDefinedByTheVulcanClassLoaderAreAccepted() throws Exception {
        ClassLoader testLoader = VulcanBehaviorIntegrationTest.class.getClassLoader();
        Plugin sameLoaderPlugin = plugin(testLoader);
        try (URLClassLoader isolated = new URLClassLoader(new URL[0], testLoader)) {
            Plugin otherLoaderPlugin = plugin(isolated);
            Event event = new ForeignFlagEvent();

            assertTrue(VulcanBehaviorIntegration.isVulcanDefinedEvent(event, sameLoaderPlugin));
            assertFalse(VulcanBehaviorIntegration.isVulcanDefinedEvent(event, otherLoaderPlugin),
                    "an event class from another plugin's class loader must be rejected");
            assertFalse(VulcanBehaviorIntegration.isVulcanDefinedEvent(null, sameLoaderPlugin));
        }
    }

    private static Plugin plugin(ClassLoader loader) {
        return (Plugin) Proxy.newProxyInstance(loader, new Class<?>[] {Plugin.class},
                (proxy, method, arguments) -> {
                    throw new UnsupportedOperationException(method.getName());
                });
    }
}
