package com.ellan.mcace.fabric;

import com.ellan.mcace.client.federation.FederationTokenVault.PreparedPresentation;
import java.time.Clock;
import java.util.Objects;
import net.minecraft.client.MinecraftClient;

/** Owns the distinct target-import prompt for one exact prepared presentation capability. */
final class FederationImportConsentController {
    interface Sender {
        void allowed(PreparedPresentation presentation);
        void declined(PreparedPresentation presentation);
        void cancelled(PreparedPresentation presentation);
    }

    private final Clock clock;
    private Pending pending;

    FederationImportConsentController(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    void accept(MinecraftClient client, PreparedPresentation presentation,
            Runnable firstRendered, Sender sender) {
        Objects.requireNonNull(client, "client");
        Objects.requireNonNull(presentation, "presentation");
        Objects.requireNonNull(firstRendered, "firstRendered");
        Objects.requireNonNull(sender, "sender");
        cancel(client);
        if (expired(presentation)) {
            sender.declined(presentation);
            return;
        }
        Pending next = new Pending(presentation, sender, client.currentScreen);
        FederationImportConsentScreen screen = new FederationImportConsentScreen(
                next.previous, presentation, firstRendered, allowed -> decide(client, next, allowed));
        next.screen = screen;
        pending = next;
        client.setScreen(screen);
    }

    void tick(MinecraftClient client) {
        Pending current = pending;
        if (current == null) return;
        if (expired(current.presentation)) {
            decide(client, current, false);
        } else if (client.currentScreen != current.screen) {
            cancel(client);
        }
    }

    /** Connection or foreign-screen cancellation releases the reservation and never sends it. */
    void cancel(MinecraftClient client) {
        Pending current = pending;
        pending = null;
        if (current == null) return;
        if (client.currentScreen == current.screen) {
            client.setScreen(current.previous);
        }
        current.sender.cancelled(current.presentation);
    }

    static boolean isCurrent(Object active, Object candidate) {
        return active != null && active == candidate;
    }

    private void decide(MinecraftClient client, Pending current, boolean allowed) {
        if (!isCurrent(pending, current)) return;
        pending = null;
        if (client.currentScreen == current.screen) {
            client.setScreen(current.previous);
        }
        if (allowed && !expired(current.presentation)) {
            current.sender.allowed(current.presentation);
        } else {
            current.sender.declined(current.presentation);
        }
    }

    private boolean expired(PreparedPresentation presentation) {
        return presentation.expiresAtEpochMs() <= clock.millis();
    }

    private static final class Pending {
        private final PreparedPresentation presentation;
        private final Sender sender;
        private final net.minecraft.client.gui.screen.Screen previous;
        private FederationImportConsentScreen screen;

        private Pending(PreparedPresentation presentation, Sender sender,
                net.minecraft.client.gui.screen.Screen previous) {
            this.presentation = presentation;
            this.sender = sender;
            this.previous = previous;
        }
    }
}
