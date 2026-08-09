package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class VelocityDeferredAdmissionRoutesTest {
    private static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000004");
    private static final Object PLAYER_IDENTITY = new Object();
    private static final VelocityLoginLifecycle.LoginTicket LOGIN_TICKET =
            new VelocityLoginLifecycle.LoginTicket(201L);

    @Test
    void baselinePermitRetainsAuthenticatedSessionAndIgnoresOldPostConnectGeneration() {
        VelocityDeferredAdmissionRoutes routes = new VelocityDeferredAdmissionRoutes(
                Clock.fixed(Instant.parse("2026-08-09T00:00:00Z"), ZoneOffset.UTC));
        assertTrue(routes.defer(PLAYER, "authenticated-session", 11L, LOGIN_TICKET, PLAYER_IDENTITY));

        assertTrue(routes.claim(PLAYER, 10L, LOGIN_TICKET, PLAYER_IDENTITY).isEmpty());
        VelocityDeferredAdmissionRoutes.Entry entry = routes.claim(
                PLAYER, 11L, LOGIN_TICKET, PLAYER_IDENTITY).orElseThrow();
        assertEquals("authenticated-session", entry.sessionId());
        assertEquals(11L, entry.generation());
    }

    @Test
    void laterLoginBaselinePermitReplacesEarlierSessionAndOnlyNewGenerationClaims() {
        VelocityDeferredAdmissionRoutes routes = new VelocityDeferredAdmissionRoutes(
                Clock.fixed(Instant.parse("2026-08-09T00:00:00Z"), ZoneOffset.UTC));
        assertTrue(routes.defer(PLAYER, "session-a", 7L, LOGIN_TICKET, PLAYER_IDENTITY));
        assertTrue(routes.defer(PLAYER, "session-b", 9L, LOGIN_TICKET, PLAYER_IDENTITY));
        assertTrue(routes.claim(PLAYER, 7L, LOGIN_TICKET, PLAYER_IDENTITY).isEmpty());
        VelocityDeferredAdmissionRoutes.Entry current = routes.claim(
                PLAYER, 9L, LOGIN_TICKET, PLAYER_IDENTITY).orElseThrow();
        assertEquals("session-b", current.sessionId());
    }

    @Test
    void stalePostConnectCannotClaimReplacementLoginPermit() {
        VelocityDeferredAdmissionRoutes routes = new VelocityDeferredAdmissionRoutes(
                Clock.fixed(Instant.parse("2026-08-09T00:00:00Z"), ZoneOffset.UTC));
        Object oldPlayer = new Object();
        Object newPlayer = new Object();
        VelocityLoginLifecycle.LoginTicket oldTicket = new VelocityLoginLifecycle.LoginTicket(401L);
        VelocityLoginLifecycle.LoginTicket newTicket = new VelocityLoginLifecycle.LoginTicket(402L);

        assertTrue(routes.defer(PLAYER, "new-session", 9L, newTicket, newPlayer));
        assertTrue(routes.claim(PLAYER, 9L, oldTicket, oldPlayer).isEmpty());
        assertEquals("new-session", routes.claim(PLAYER, 9L, newTicket, newPlayer)
                .orElseThrow().sessionId());
    }
}
