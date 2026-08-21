package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent;
import com.ellan.mcace.core.proxy.ProxyPolicyRefreshStatus;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class BungeeDeferredDispositionRoutesTest {
    private static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final Instant NOW = Instant.parse("2026-08-09T00:00:00Z");

    @Test
    void initialBackendRouteIsSessionAndPhysicalLoginBoundAndClaimedOnlyAfterSuccessfulBackendEvent() {
        BungeeDeferredDispositionRoutes routes = routes();
        Object connection = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket ticket = routes.beginLogin(PLAYER, connection);
        assertFalse(routes.isReady(PLAYER, connection, ticket));
        assertEquals(BungeeDeferredDispositionRoutes.DeferResult.QUEUED,
                routes.deferDisposition(event("session-a", DispositionAction.LIMIT), "limited", ticket, connection));
        assertTrue(routes.claimForReadyBackend(PLAYER, connection, ticket).isEmpty());

        assertEquals(Optional.of(ticket), routes.markBackendReady(PLAYER, connection));
        BungeeDeferredDispositionRoutes.Pending pending =
                routes.claimForReadyBackend(PLAYER, connection, ticket).orElseThrow();
        assertEquals("session-a", pending.sessionId());
        assertEquals("limited", pending.targetName());
        assertEquals(BungeeDeferredDispositionRoutes.Source.DISPOSITION, pending.source());
        assertTrue(routes.claimForReadyBackend(PLAYER, connection, ticket).isEmpty(),
                "manual later switches cannot revive it");
    }

    @Test
    void backendConnectingClosesOnlyTheExactCurrentLoginActionWindow() {
        BungeeDeferredDispositionRoutes routes = routes();
        Object connection = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket ticket = routes.beginLogin(PLAYER, connection);
        assertEquals(Optional.of(ticket), routes.markBackendReady(PLAYER, connection));
        assertTrue(routes.isReady(PLAYER, connection, ticket));

        assertFalse(routes.markBackendConnecting(PLAYER, new Object(), ticket));
        assertTrue(routes.isReady(PLAYER, connection, ticket),
                "a stale connection identity cannot close the current action window");
        assertFalse(routes.markBackendConnecting(
                PLAYER, connection, new BungeeDeferredDispositionRoutes.LoginTicket(99L)));
        assertTrue(routes.isReady(PLAYER, connection, ticket),
                "a stale login ticket cannot close the current action window");

        assertTrue(routes.markBackendConnecting(PLAYER, connection, ticket));
        assertFalse(routes.isReady(PLAYER, connection, ticket));
        assertEquals(Optional.of(ticket), routes.markBackendReady(PLAYER, connection));
        assertTrue(routes.isReady(PLAYER, connection, ticket));
    }

    @Test
    void disconnectReconnectCannotReuseTicketOrLetOldReadyOrRetryClaimNewPending() {
        BungeeDeferredDispositionRoutes routes = routes();
        Object oldConnection = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket oldTicket = routes.beginLogin(PLAYER, oldConnection);
        assertEquals(BungeeDeferredDispositionRoutes.DeferResult.QUEUED,
                routes.deferDisposition(event("session-old", DispositionAction.LIMIT), "limited", oldTicket, oldConnection));
        assertTrue(routes.clear(PLAYER, oldConnection, oldTicket));

        Object newConnection = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket newTicket = routes.beginLogin(PLAYER, newConnection);
        assertNotEquals(oldTicket, newTicket, "a reconnect must never reuse a former ticket");
        assertEquals(BungeeDeferredDispositionRoutes.DeferResult.QUEUED,
                routes.deferDisposition(event("session-new", DispositionAction.QUARANTINE), "quarantine", newTicket, newConnection));

        assertEquals(Optional.empty(), routes.markBackendReady(PLAYER, oldConnection),
                "a late old ServerConnectedEvent must not mark the reconnect ready");
        assertTrue(routes.claimForReadyBackend(PLAYER, oldConnection, oldTicket).isEmpty(),
                "a late old scheduled retry must not consume the reconnect pending route");
        assertFalse(routes.isReady(PLAYER, newConnection, newTicket));

        assertEquals(Optional.of(newTicket), routes.markBackendReady(PLAYER, newConnection));
        assertEquals("session-new", routes.claimForReadyBackend(PLAYER, newConnection, newTicket)
                .orElseThrow().sessionId());
    }

    @Test
    void staleDisconnectAndDenyCannotAffectNewPhysicalLogin() {
        BungeeDeferredDispositionRoutes routes = routes();
        Object oldConnection = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket oldTicket = routes.beginLogin(PLAYER, oldConnection);
        Object newConnection = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket newTicket = routes.beginLogin(PLAYER, newConnection);

        assertFalse(routes.clear(PLAYER, oldConnection, oldTicket));
        assertFalse(routes.markDenied(PLAYER, "session-old", oldConnection, oldTicket));
        assertTrue(routes.isCurrent(PLAYER, newConnection, newTicket));
        assertTrue(routes.permitRoute(PLAYER, "session-new", newConnection, newTicket));

        assertTrue(routes.markDenied(PLAYER, "session-new", newConnection, newTicket));
        assertFalse(routes.permitRoute(PLAYER, "session-new", newConnection, newTicket));
        assertFalse(routes.permitRoute(PLAYER, "replacement-session", newConnection, newTicket),
                "session churn within one physical login cannot clear terminal DENY");
        assertFalse(routes.permitRoute(PLAYER, "session-old", oldConnection, oldTicket));
    }

    @Test
    void generationMismatchCapacityAndHeartbeatRecoveryFailClosed() {
        BungeeDeferredDispositionRoutes routes = routes();
        Object connection = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket ticket = routes.beginLogin(PLAYER, connection);
        assertEquals(BungeeDeferredDispositionRoutes.DeferResult.STALE_SESSION_REJECTED,
                routes.deferHeartbeat(PLAYER, "session-a", "limited", new BungeeDeferredDispositionRoutes.LoginTicket(99L), connection));
        assertEquals(BungeeDeferredDispositionRoutes.DeferResult.QUEUED,
                routes.deferHeartbeat(PLAYER, "session-a", "limited", ticket, connection));
        routes.clearHeartbeat(PLAYER, "session-a", connection, ticket);
        routes.markBackendReady(PLAYER, connection);
        assertTrue(routes.claimForReadyBackend(PLAYER, connection, ticket).isEmpty());

        for (int index = 0; index < BungeeDeferredDispositionRoutes.MAX_PENDING; index++) {
            UUID player = new UUID(0L, index + 2L);
            Object playerConnection = new Object();
            BungeeDeferredDispositionRoutes.LoginTicket playerTicket = routes.beginLogin(player, playerConnection);
            assertEquals(BungeeDeferredDispositionRoutes.DeferResult.QUEUED,
                    routes.deferHeartbeat(player, "s-" + index, "limited", playerTicket, playerConnection));
        }
        UUID overflow = new UUID(0L, 9999L);
        Object overflowConnection = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket overflowTicket = routes.beginLogin(overflow, overflowConnection);
        assertEquals(BungeeDeferredDispositionRoutes.DeferResult.CAPACITY_REJECTED,
                routes.deferHeartbeat(overflow, "overflow", "limited", overflowTicket, overflowConnection));
        assertEquals(BungeeDeferredDispositionRoutes.MAX_PENDING, routes.pendingCount());
    }

    @Test
    void strongerQuarantineSupersedesLimitWithinSameSession() {
        BungeeDeferredDispositionRoutes routes = routes();
        Object connection = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket ticket = routes.beginLogin(PLAYER, connection);
        assertEquals(BungeeDeferredDispositionRoutes.DeferResult.QUEUED,
                routes.deferDisposition(event("session-a", DispositionAction.LIMIT), "limited", ticket, connection));
        assertEquals(BungeeDeferredDispositionRoutes.DeferResult.SUPERSEDED,
                routes.deferDisposition(event("session-a", DispositionAction.QUARANTINE), "quarantine", ticket, connection));
        routes.markBackendReady(PLAYER, connection);
        BungeeDeferredDispositionRoutes.Pending pending =
                routes.claimForReadyBackend(PLAYER, connection, ticket).orElseThrow();
        assertEquals(DispositionAction.QUARANTINE, pending.action());
        assertEquals("quarantine", pending.targetName());
    }

    @Test
    void exhaustedProcessTicketSpaceFailsClosedInsteadOfReusingAnOldTicket() throws Exception {
        BungeeDeferredDispositionRoutes routes = routes();
        java.lang.reflect.Field sequence = BungeeDeferredDispositionRoutes.class
                .getDeclaredField("nextLoginTicket");
        sequence.setAccessible(true);
        sequence.setLong(routes, Long.MAX_VALUE);
        Object connection = new Object();

        assertThrows(IllegalStateException.class,
                () -> routes.beginLogin(PLAYER, connection));
        assertTrue(routes.ticketFor(PLAYER, connection).isEmpty());
    }

    private static BungeeDeferredDispositionRoutes routes() {
        return new BungeeDeferredDispositionRoutes(Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static AuthenticatedManifestDispositionEvent event(String session, DispositionAction action) {
        return new AuthenticatedManifestDispositionEvent(
                PLAYER, session, NOW, action, Optional.of("rule"), ProxyPolicyRefreshStatus.ACTIVE,
                Optional.of("policy"), Optional.of(1L), Optional.of(NOW.plusSeconds(30)),
                ObservationOrigin.SERVER_CONFIRMED,
                Optional.of(UUID.fromString("00000000-0000-0000-0000-000000000099")),
                Optional.empty(), Optional.of("33".repeat(32)));
    }
}
