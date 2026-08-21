package com.ellan.mcace.fabric;

import com.ellan.mcace.client.policy.VerifiedPolicy;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import net.minecraft.client.Minecraft;

/** One connection-bound explicit-file authorization prompt at a time; nothing is persisted. */
final class ExplicitFileConsentController {
    private Pending pending;

    void accept(Minecraft client, VerifiedPolicy policy, Set<String> requestedFiles,
            Runnable rendered, Consumer<Set<String>> allowed, Runnable declined) {
        Objects.requireNonNull(client, "client");
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(requestedFiles, "requestedFiles");
        Objects.requireNonNull(rendered, "rendered");
        Objects.requireNonNull(allowed, "allowed");
        Objects.requireNonNull(declined, "declined");
        cancel(client);
        List<String> files = requestedFiles.stream().sorted().toList();
        if (!validDisplayRequest(files)) {
            declined.run();
            return;
        }
        Pending next = new Pending(Set.copyOf(files), allowed, declined,
                ConsentUiSupport.currentScreen(client));
        pending = next;
        ConsentUiSupport.setScreen(client, new ExplicitFileConsentScreen(
                next.previous(), policy, files, rendered,
                decision -> decide(client, next, decision)));
    }

    void cancel(Minecraft client) {
        Pending current = pending;
        pending = null;
        if (current == null) return;
        if (ConsentUiSupport.currentScreen(client) instanceof ExplicitFileConsentScreen screen
                && screen.previous() == current.previous()) {
            ConsentUiSupport.setScreen(client, current.previous());
        }
        current.declined().run();
    }

    static boolean isCurrent(Object active, Object candidate) {
        return active != null && active == candidate;
    }

    static boolean validDisplayRequest(List<String> files) {
        return !files.isEmpty() && files.size() <= 128
                && files.stream().allMatch(path -> path != null && !path.isBlank()
                        && path.length() <= 512 && path.chars().noneMatch(Character::isISOControl));
    }

    private void decide(Minecraft client, Pending current, boolean allowed) {
        if (!isCurrent(pending, current)) return;
        pending = null;
        ConsentUiSupport.setScreen(client, current.previous());
        if (allowed) current.allowed().accept(current.files());
        else current.declined().run();
    }

    private record Pending(Set<String> files, Consumer<Set<String>> allowed, Runnable declined,
                           net.minecraft.client.gui.screens.Screen previous) { }
}
