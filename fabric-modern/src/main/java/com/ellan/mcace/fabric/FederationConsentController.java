package com.ellan.mcace.fabric;

import com.ellan.mcace.client.session.ClientHandshakeEngine.VerifiedFederationConsentRequest;
import java.time.Clock;
import java.util.Objects;
import net.minecraft.client.Minecraft;

/** One visible federation decision at a time; it creates no wire response when declined. */
final class FederationConsentController {
    interface Sender {
        void allowed(VerifiedFederationConsentRequest request);
        void declined(VerifiedFederationConsentRequest request);
    }

    private final Clock clock;
    private Pending pending;

    FederationConsentController(Clock clock) { this.clock = Objects.requireNonNull(clock, "clock"); }

    void accept(Minecraft client, VerifiedFederationConsentRequest request,
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
        Pending next = new Pending(request, sender, ConsentUiSupport.currentScreen(client));
        FederationConsentScreen screen = new FederationConsentScreen(
                next.previous, request, firstRendered, allowed -> decide(client, next, allowed));
        next.screen = screen;
        pending = next;
        ConsentUiSupport.setScreen(client, screen);
    }

    void tick(Minecraft client) {
        Pending current = pending;
        if (current == null) return;
        if (expired(current.request)) {
            decide(client, current, false);
        } else if (ConsentUiSupport.currentScreen(client) != current.screen) {
            cancel(client);
        }
    }

    void cancel(Minecraft client) {
        Pending current = pending;
        pending = null;
        if (current != null) {
            if (ConsentUiSupport.currentScreen(client) == current.screen) {
                ConsentUiSupport.setScreen(client, current.previous);
            }
            current.sender.declined(current.request);
        }
    }

    static boolean isCurrent(Object active, Object candidate) { return active != null && active == candidate; }

    private void decide(Minecraft client, Pending current, boolean allowed) {
        if (!isCurrent(pending, current)) return;
        pending = null;
        if (ConsentUiSupport.currentScreen(client) == current.screen) {
            ConsentUiSupport.setScreen(client, current.previous);
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
        private final net.minecraft.client.gui.screens.Screen previous;
        private FederationConsentScreen screen;

        private Pending(VerifiedFederationConsentRequest request, Sender sender,
                net.minecraft.client.gui.screens.Screen previous) {
            this.request = request;
            this.sender = sender;
            this.previous = previous;
        }
    }
}
