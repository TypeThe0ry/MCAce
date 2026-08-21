package com.ellan.mcace.fabric;

import com.ellan.mcace.client.session.ClientHandshakeEngine.VerifiedFederationConsentRequest;
import java.time.Clock;
import java.util.Objects;
import net.minecraft.client.MinecraftClient;

/** One visible federation decision at a time; it creates no wire response when declined. */
final class FederationConsentController {
    interface Sender {
        void allowed(VerifiedFederationConsentRequest request);
        void declined(VerifiedFederationConsentRequest request);
    }

    private final Clock clock;
    private Pending pending;

    FederationConsentController(Clock clock) { this.clock = Objects.requireNonNull(clock, "clock"); }

    void accept(MinecraftClient client, VerifiedFederationConsentRequest request,
            Runnable firstRendered, Sender sender) {
        Objects.requireNonNull(client, "client");
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(firstRendered, "firstRendered");
        Objects.requireNonNull(sender, "sender");
        cancel(client);
        if (expired(request)) {
            sender.declined(request);
            return;
        }
        Pending next = new Pending(request, sender, client.currentScreen);
        FederationConsentScreen screen = new FederationConsentScreen(
                next.previous, request, firstRendered, allowed -> decide(client, next, allowed));
        next.screen = screen;
        pending = next;
        client.setScreen(screen);
    }

    void tick(MinecraftClient client) {
        Pending current = pending;
        if (current == null) return;
        if (expired(current.request)) {
            decide(client, current, false);
        } else if (client.currentScreen != current.screen) {
            cancel(client);
        }
    }

    void cancel(MinecraftClient client) {
        Pending current = pending;
        pending = null;
        if (current != null) {
            if (client.currentScreen == current.screen) {
                client.setScreen(current.previous);
            }
            current.sender.declined(current.request);
        }
    }

    static boolean isCurrent(Object active, Object candidate) { return active != null && active == candidate; }

    private void decide(MinecraftClient client, Pending current, boolean allowed) {
        if (!isCurrent(pending, current)) return;
        pending = null;
        if (client.currentScreen == current.screen) {
            client.setScreen(current.previous);
        }
        if (allowed && !expired(current.request)) current.sender.allowed(current.request);
        else current.sender.declined(current.request);
    }

    private boolean expired(VerifiedFederationConsentRequest request) {
        return request.request().getExpiresAtEpochMs() <= clock.millis();
    }

    private static final class Pending {
        private final VerifiedFederationConsentRequest request;
        private final Sender sender;
        private final net.minecraft.client.gui.screen.Screen previous;
        private FederationConsentScreen screen;

        private Pending(VerifiedFederationConsentRequest request, Sender sender,
                net.minecraft.client.gui.screen.Screen previous) {
            this.request = request;
            this.sender = sender;
            this.previous = previous;
        }
    }
}
