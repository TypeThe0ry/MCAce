package com.ellan.mcace.fabric;

import com.ellan.mcace.client.policy.VerifiedPolicy;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import net.minecraft.client.Minecraft;

/**
 * Owns the single connection-bound MCAce enablement decision.  No decision is persisted and
 * closing the screen is exactly the same as declining it.
 */
final class MCAceEnablementController {
    private Pending pending;

    void request(Minecraft client, VerifiedPolicy policy, Set<String> requestedFiles,
            Runnable rendered, Consumer<Set<String>> enabled, Runnable declined) {
        Objects.requireNonNull(client, "client");
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(requestedFiles, "requestedFiles");
        Objects.requireNonNull(rendered, "rendered");
        Objects.requireNonNull(enabled, "enabled");
        Objects.requireNonNull(declined, "declined");
        cancel(client);
        List<String> files = requestedFiles.stream().sorted().toList();
        if (!validDisplayRequest(files)) {
            declined.run();
            return;
        }
        Pending next = new Pending(files, enabled, declined, ConsentUiSupport.currentScreen(client));
        pending = next;
        ConsentUiSupport.setScreen(client, ExplicitFileConsentScreen.forEnablement(
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
        return files.size() <= 128 && files.stream().allMatch(path -> path != null && !path.isBlank()
                && path.length() <= 512 && path.chars().noneMatch(Character::isISOControl));
    }

    private void decide(Minecraft client, Pending current, boolean allow) {
        if (!isCurrent(pending, current)) return;
        pending = null;
        ConsentUiSupport.setScreen(client, current.previous());
        if (allow) current.enabled().accept(Set.copyOf(current.files()));
        else current.declined().run();
    }

    private record Pending(List<String> files, Consumer<Set<String>> enabled, Runnable declined,
                           net.minecraft.client.gui.screens.Screen previous) {
        private Pending {
            files = List.copyOf(files);
        }
    }
}
