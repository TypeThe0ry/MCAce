package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

final class DisconnectConsentCancellationTest {
    @Test void networkCancellationDeclinesEnablementWithoutMinecraftUi() throws Exception {
        var controller = new MCAceEnablementController();
        check(controller, true, controller::cancelWithoutUi);
    }

    @Test void networkCancellationDeclinesExplicitFilesWithoutMinecraftUi() throws Exception {
        var controller = new ExplicitFileConsentController();
        check(controller, false, controller::cancelWithoutUi);
    }

    private static void check(Object controller, boolean enablement, Runnable cancel) throws Exception {
        var pendingField = controller.getClass().getDeclaredField("pending");
        pendingField.setAccessible(true);
        var constructor = pendingField.getType().getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        var declines = new AtomicInteger();
        var approvals = new AtomicInteger();
        Consumer<Set<String>> allowed = ignored -> approvals.incrementAndGet();
        Runnable declined = declines::incrementAndGet;
        // Null previous screen deliberately requires cancellation to avoid all Minecraft UI access.
        Object pending = enablement
                ? constructor.newInstance(List.of("options.txt"), allowed, declined, null, 1L, 1L)
                : constructor.newInstance(Set.of("options.txt"), allowed, declined, null);
        pendingField.set(controller, pending);
        CompletableFuture.runAsync(cancel).get(5, TimeUnit.SECONDS);
        assertNull(pendingField.get(controller));
        assertEquals(1, declines.get());
        assertEquals(0, approvals.get());
        cancel.run();
        assertEquals(1, declines.get());
    }
}
