package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

final class VelocityLoginLifecycleTest {
    private static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000006");

    @Test
    void newPostLoginBeforeOldDisconnectMakesEveryOldAsyncBoundaryStale() {
        VelocityLoginLifecycle lifecycle = new VelocityLoginLifecycle();
        Object oldPlayer = new Object();
        Object newPlayer = new Object();
        VelocityLoginLifecycle.LoginTicket oldTicket = lifecycle.beginLogin(PLAYER, oldPlayer);

        // Models the lifecycle-locked publication performed by the replacement PostLogin.
        VelocityLoginLifecycle.LoginTicket newTicket = lifecycle.beginLogin(PLAYER, newPlayer);

        assertNotEquals(oldTicket, newTicket);
        assertFalse(lifecycle.isCurrent(PLAYER, oldPlayer, oldTicket),
                "old delayed handshake/plugin/route/DENY/callback work must all fail this gate");
        assertFalse(lifecycle.clear(PLAYER, oldPlayer, oldTicket),
                "the predecessor Disconnect must not clear its replacement");
        assertTrue(lifecycle.isCurrent(PLAYER, newPlayer, newTicket));
        assertSame(newPlayer, lifecycle.current(PLAYER).orElseThrow().playerIdentity());
    }

    @Test
    void ticketsAreProcessGlobalAndAreNotReusedByANewRegistryInstance() {
        VelocityLoginLifecycle first = new VelocityLoginLifecycle();
        VelocityLoginLifecycle second = new VelocityLoginLifecycle();
        VelocityLoginLifecycle.LoginTicket firstTicket = first.beginLogin(PLAYER, new Object());
        VelocityLoginLifecycle.LoginTicket secondTicket = second.beginLogin(PLAYER, new Object());

        assertNotEquals(firstTicket, secondTicket);
        assertTrue(Long.compareUnsigned(secondTicket.value(), firstTicket.value()) > 0);
    }

    @Test
    void challengeMarkerIsTicketBoundAcrossReplacementAndStaleCleanup() {
        Map<UUID, VelocityLoginLifecycle.LoginTicket> challenges = new HashMap<>();
        VelocityLoginLifecycle lifecycle = new VelocityLoginLifecycle();
        VelocityLoginLifecycle.LoginTicket oldTicket = lifecycle.beginLogin(PLAYER, new Object());
        assertTrue(MCAceVelocityPlugin.installTicketBoundChallenge(challenges, PLAYER, oldTicket));

        assertTrue(MCAceVelocityPlugin.removeTicketBoundChallenge(challenges, PLAYER, oldTicket));
        VelocityLoginLifecycle.LoginTicket newTicket = lifecycle.beginLogin(PLAYER, new Object());
        assertTrue(MCAceVelocityPlugin.installTicketBoundChallenge(challenges, PLAYER, newTicket));

        assertFalse(MCAceVelocityPlugin.removeTicketBoundChallenge(challenges, PLAYER, oldTicket));
        assertTrue(challenges.containsValue(newTicket));
    }

    @Test
    void connectionCompletionIsConsumedExactlyOnceForSuccessFailureOrLateDelivery() {
        AtomicBoolean completion = new AtomicBoolean();
        assertTrue(MCAceVelocityPlugin.consumeRouteCompletion(completion));
        assertFalse(MCAceVelocityPlugin.consumeRouteCompletion(completion));
        assertFalse(MCAceVelocityPlugin.consumeRouteCompletion(completion));
    }
}
