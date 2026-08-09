package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.DispositionCatalogPreview;
import com.ellan.mcace.protocol.generated.DetectionCatalogCategory;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import net.md_5.bungee.api.CommandSender;
import net.md_5.bungee.api.chat.BaseComponent;
import org.junit.jupiter.api.Test;

final class MCAceBungeeCommandTest {
    @Test
    void readOnlyCatalogCommandsRequireCheckPermission() {
        AtomicInteger previews = new AtomicInteger();
        MCAceBungeeCommand command = command(previews, new AtomicInteger());
        List<String> messages = new ArrayList<>();

        command.execute(sender(false, true, messages), new String[] {"disposition", "catalog", "preview"});

        assertEquals(0, previews.get());
        assertFalse(messages.isEmpty());
    }

    @Test
    void catalogPublishRequiresPolicyPermissionButNotCheckPermission() {
        AtomicInteger previews = new AtomicInteger();
        AtomicInteger publishes = new AtomicInteger();
        MCAceBungeeCommand command = command(previews, publishes);
        List<String> messages = new ArrayList<>();

        command.execute(sender(false, true, messages),
                new String[] {"disposition", "catalog", "publish"});

        assertEquals(1, previews.get());
        assertEquals(1, publishes.get());
        assertFalse(messages.isEmpty());
    }

    @Test
    void catalogReportsEffectiveExecutionModeSupplier() {
        AtomicInteger previews = new AtomicInteger();
        MCAceBungeeCommand command = command(
                previews, new AtomicInteger(), BungeeDispositionExecutionMode.MONITOR);
        List<String> messages = new ArrayList<>();

        command.execute(sender(true, false, messages),
                new String[] {"disposition", "catalog", "preview"});

        assertEquals(1, previews.get());
        assertTrue(messages.stream().anyMatch(message -> message.contains("mode=MONITOR")));
        assertFalse(messages.stream().anyMatch(message -> message.contains("mode=LIMITED_ROUTE")));
    }

    private static MCAceBungeeCommand command(AtomicInteger previews, AtomicInteger publishes) {
        return command(previews, publishes, BungeeDispositionExecutionMode.MONITOR);
    }

    private static MCAceBungeeCommand command(
            AtomicInteger previews,
            AtomicInteger publishes,
            BungeeDispositionExecutionMode effectiveMode) {
        BungeeDispositionPolicyPublisher publisher = new BungeeDispositionPolicyPublisher() {
            @Override
            public BungeePublishedDispositionPolicy publish() {
                publishes.incrementAndGet();
                return new BungeePublishedDispositionPolicy("test", 2, 2);
            }

            @Override
            public DispositionCatalogPreview preview() {
                previews.incrementAndGet();
                return new DispositionCatalogPreview(
                        2, 2, 2,
                        Map.of(DetectionCatalogCategory.ACCESSIBILITY, 1,
                                DetectionCatalogCategory.UTILITY, 1),
                        Map.of(DispositionAction.ALLOW, 1), List.of());
            }
        };
        return new MCAceBungeeCommand(
                new InMemoryMCAceApi(),
                () -> new BungeeDispositionStatus(
                        com.ellan.mcace.core.proxy.ProxyPolicyRefreshStatus.ACTIVE, Optional.of(1L)),
                () -> Optional.of(publisher),
                () -> effectiveMode);
    }

    private static CommandSender sender(
            boolean checkPermission, boolean policyPermission, List<String> messages) {
        return (CommandSender) Proxy.newProxyInstance(
                MCAceBungeeCommandTest.class.getClassLoader(),
                new Class<?>[] {CommandSender.class},
                (proxy, method, arguments) -> {
                    if ("hasPermission".equals(method.getName())) {
                        String permission = String.valueOf(arguments[0]);
                        return "mcace.admin.check".equals(permission)
                                ? checkPermission : policyPermission;
                    }
                    if (method.getName().startsWith("sendMessage")) {
                        Object message = arguments == null || arguments.length == 0 ? null : arguments[0];
                        if (message instanceof BaseComponent component) {
                            messages.add(component.toPlainText());
                        } else if (message instanceof BaseComponent[] components) {
                            messages.add(BaseComponent.toPlainText(components));
                        } else {
                            messages.add(method.getName());
                        }
                    }
                    if (method.getReturnType() == boolean.class) return false;
                    if (method.getReturnType() == int.class) return 0;
                    return null;
                });
    }
}
