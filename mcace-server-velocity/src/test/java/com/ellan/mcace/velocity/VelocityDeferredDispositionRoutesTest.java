package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent;
import com.ellan.mcace.core.proxy.ProxyPolicyRefreshStatus;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** Covers the adapter-owned bounded state used between CONFIGURATION and backend readiness. */
final class VelocityDeferredDispositionRoutesTest {
    private static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final Instant NOW = Instant.parse("2026-08-09T00:00:00Z");

    @Test
    void configurationDeferredRouteIsClaimedOnceAtTheFirstPostConnect() {
        RoutesHarness routes = routes(NOW);
        assertEquals(VelocityDeferredDispositionRoutes.DeferResult.QUEUED,
                routes.defer(event(DispositionAction.LIMIT, "session-a"), "limited", 7L));

        VelocityDeferredDispositionRoutes.Pending first = routes.claimForPostConnect(PLAYER, 7L).orElseThrow();
        assertEquals("limited", first.targetName());
        assertEquals("session-a", first.event().sessionId());
        assertTrue(routes.claimForPostConnect(PLAYER, 7L).isEmpty());
        assertEquals(0, routes.pendingCount());
    }

    @Test
    void strongerQuarantineDeterministicallySupersedesLimitButLimitCannotDowngradeIt() {
        RoutesHarness routes = routes(NOW);
        routes.defer(event(DispositionAction.LIMIT, "session-a"), "limited", 7L);
        assertEquals(VelocityDeferredDispositionRoutes.DeferResult.SUPERSEDED,
                routes.defer(event(DispositionAction.QUARANTINE, "session-a"), "quarantine", 7L));
        assertEquals(VelocityDeferredDispositionRoutes.DeferResult.ALREADY_STRONGER,
                routes.defer(event(DispositionAction.LIMIT, "session-a"), "limited", 7L));

        VelocityDeferredDispositionRoutes.Pending pending = routes.claimForPostConnect(PLAYER, 7L).orElseThrow();
        assertEquals(DispositionAction.QUARANTINE, pending.event().highestAction());
        assertEquals("quarantine", pending.targetName());
    }

    @Test
    void disconnectOrSessionCleanupDropsPendingRoute() {
        RoutesHarness routes = routes(NOW);
        routes.defer(event(DispositionAction.LIMIT, "session-a"), "limited", 7L);
        routes.clearSession(PLAYER, "session-a");
        assertTrue(routes.claimForPostConnect(PLAYER, 7L).isEmpty());

        routes.defer(event(DispositionAction.LIMIT, "session-b"), "limited", 7L);
        routes.clear(PLAYER);
        assertTrue(routes.claimForPostConnect(PLAYER, 7L).isEmpty());
    }

    @Test
    void oldPostConnectGenerationCannotConsumeANewSessionPendingRoute() {
        RoutesHarness routes = routes(NOW);
        routes.defer(event(DispositionAction.LIMIT, "new-session"), "limited", 9L);
        assertTrue(routes.claimForPostConnect(PLAYER, 8L).isEmpty());
        assertEquals("new-session", routes.claimForPostConnect(PLAYER, 9L)
                .orElseThrow().event().sessionId());
    }

    @Test
    void denyAtomicallyDropsPendingAndRejectsLaterSameSessionRoutes() {
        RoutesHarness routes = routes(NOW);
        routes.defer(event(DispositionAction.LIMIT, "session-a"), "limited", 7L);
        routes.markDenied(PLAYER, "session-a");

        assertTrue(routes.claimForPostConnect(PLAYER, 7L).isEmpty());
        assertFalse(routes.permitRoute(PLAYER, "session-a"));
        assertEquals(VelocityDeferredDispositionRoutes.DeferResult.TERMINAL_REJECTED,
                routes.defer(event(DispositionAction.QUARANTINE, "session-a"), "quarantine", 7L));
        routes.resetForCurrentSession(PLAYER, "session-b");
        assertFalse(routes.permitRoute(PLAYER, "session-b"),
                "session churn within one physical login cannot clear terminal DENY");
    }

    @Test
    void concurrentDenyAndDeferredRouteLeaveNoRunnableSameSessionRoute() throws Exception {
        RoutesHarness routes = routes(NOW);
        CountDownLatch start = new CountDownLatch(1);
        Thread deny = new Thread(() -> await(start, () -> routes.markDenied(PLAYER, "session-a")));
        Thread defer = new Thread(() -> await(start, () ->
                routes.defer(event(DispositionAction.LIMIT, "session-a"), "limited", 7L)));
        deny.start();
        defer.start();
        start.countDown();
        deny.join(1_000);
        defer.join(1_000);

        assertFalse(deny.isAlive());
        assertFalse(defer.isAlive());
        assertFalse(routes.permitRoute(PLAYER, "session-a"));
        assertTrue(routes.claimForPostConnect(PLAYER, 7L).isEmpty());
    }

    @Test
    void terminalMarkerAndRouteRequestCreationAreLinearized() throws Exception {
        RoutesHarness routes = routes(NOW);
        AtomicBoolean deniedFirstSupplierRan = new AtomicBoolean();
        routes.markDenied(PLAYER, "session-a");
        assertEquals(VelocityDispositionExecutor.RouteOutcome.UNAVAILABLE,
                routes.executeIfPermitted(PLAYER, "session-a", () -> {
                    deniedFirstSupplierRan.set(true);
                    return VelocityDispositionExecutor.RouteOutcome.DISPATCHED;
                }));
        assertFalse(deniedFirstSupplierRan.get());

        RoutesHarness fresh = routes(NOW);
        CountDownLatch supplierEntered = new CountDownLatch(1);
        CountDownLatch releaseSupplier = new CountDownLatch(1);
        AtomicInteger invocations = new AtomicInteger();
        Thread route = new Thread(() -> fresh.executeIfPermitted(PLAYER, "session-a", () -> {
            invocations.incrementAndGet();
            supplierEntered.countDown();
            await(releaseSupplier, () -> { });
            return VelocityDispositionExecutor.RouteOutcome.DISPATCHED;
        }));
        Thread deny = new Thread(() -> fresh.markDenied(PLAYER, "session-a"));
        route.start();
        assertTrue(supplierEntered.await(1, TimeUnit.SECONDS));
        deny.start();
        releaseSupplier.countDown();
        route.join(1_000);
        deny.join(1_000);

        assertEquals(1, invocations.get());
        assertFalse(fresh.permitRoute(PLAYER, "session-a"));
        assertEquals(VelocityDispositionExecutor.RouteOutcome.UNAVAILABLE,
                fresh.executeIfPermitted(PLAYER, "session-a", () -> {
                    invocations.incrementAndGet();
                    return VelocityDispositionExecutor.RouteOutcome.DISPATCHED;
                }));
        assertEquals(1, invocations.get());
    }

    @Test
    void staleSessionCannotClearNewSessionTerminalOrReplaceItsPendingRoute() {
        RoutesHarness denied = routes(NOW);
        denied.markDenied(PLAYER, "session-b");
        assertFalse(denied.permitRoute(PLAYER, "session-a"));
        assertEquals(VelocityDeferredDispositionRoutes.DeferResult.TERMINAL_REJECTED,
                denied.defer(event(DispositionAction.LIMIT, "session-a"), "limited", 8L));
        assertFalse(denied.permitRoute(PLAYER, "session-b"));
        denied.resetForCurrentSession(PLAYER, "session-c");
        assertFalse(denied.permitRoute(PLAYER, "session-c"),
                "a late session name cannot clear DENY for the same physical login");

        RoutesHarness pending = routes(NOW);
        pending.defer(event(DispositionAction.QUARANTINE, "session-b"), "quarantine", 9L);
        assertEquals(VelocityDeferredDispositionRoutes.DeferResult.STALE_SESSION_REJECTED,
                pending.defer(event(DispositionAction.LIMIT, "session-a"), "limited", 8L));
        assertEquals("session-b", pending.claimForPostConnect(PLAYER, 9L)
                .orElseThrow().event().sessionId());
    }

    @Test
    void laterLoginGenerationReplacesAnEarlierSessionDeferredRoute() {
        RoutesHarness routes = routes(NOW);
        routes.defer(event(DispositionAction.LIMIT, "session-a"), "limited", 7L);
        assertEquals(VelocityDeferredDispositionRoutes.DeferResult.QUEUED,
                routes.defer(event(DispositionAction.QUARANTINE, "session-b"), "quarantine", 9L));
        VelocityDeferredDispositionRoutes.Pending claimed = routes.claimForPostConnect(PLAYER, 9L).orElseThrow();
        assertEquals("session-b", claimed.event().sessionId());
        assertEquals(9L, claimed.backendGeneration());
    }

    @Test
    void expiredOrPolicyExpiredRoutesCannotBeClaimedByLaterManualSwitch() {
        MutableClock clock = new MutableClock(NOW);
        RoutesHarness routes = new RoutesHarness(clock);
        routes.defer(event(DispositionAction.LIMIT, "session-a"), "limited", 7L);
        clock.advance(VelocityDeferredDispositionRoutes.MAX_AGE);
        assertTrue(routes.claimForPostConnect(PLAYER, 7L).isEmpty());

        routes.defer(expiredEvent(), "limited", 8L);
        assertTrue(routes.claimForPostConnect(PLAYER, 8L).isEmpty());
    }

    @Test
    void capacityIsStrictAndDoesNotPersistAnything() {
        RoutesHarness routes = routes(NOW);
        for (int index = 0; index < VelocityDeferredDispositionRoutes.MAX_PENDING; index++) {
            UUID player = new UUID(0L, index + 10L);
            assertEquals(VelocityDeferredDispositionRoutes.DeferResult.QUEUED,
                    routes.defer(event(player, DispositionAction.LIMIT, "session-" + index), "limited", 7L));
        }
        assertEquals(VelocityDeferredDispositionRoutes.DeferResult.CAPACITY_REJECTED,
                routes.defer(event(new UUID(1L, 1L), DispositionAction.LIMIT, "overflow"), "limited", 7L));
        assertEquals(VelocityDeferredDispositionRoutes.MAX_PENDING, routes.pendingCount());
    }

    @Test
    void delayedRouteAndDenyStateCannotCrossPhysicalLoginTickets() {
        VelocityDeferredDispositionRoutes routes = routes(NOW).delegate;
        Object oldPlayer = new Object();
        Object newPlayer = new Object();
        VelocityLoginLifecycle.LoginTicket oldTicket = new VelocityLoginLifecycle.LoginTicket(301L);
        VelocityLoginLifecycle.LoginTicket newTicket = new VelocityLoginLifecycle.LoginTicket(302L);

        assertEquals(VelocityDeferredDispositionRoutes.DeferResult.QUEUED,
                routes.defer(event(DispositionAction.LIMIT, "old-session"),
                        "limited", 7L, oldTicket, oldPlayer));
        assertTrue(routes.claimForPostConnect(PLAYER, 7L, newTicket, newPlayer).isEmpty());

        routes.clear(PLAYER);
        routes.markDenied(PLAYER, "old-session", oldTicket, oldPlayer);
        assertFalse(routes.permitRoute(PLAYER, "late-session", oldTicket, oldPlayer));
        routes.resetForCurrentSession(PLAYER, "late-session", oldTicket, oldPlayer);
        assertFalse(routes.permitRoute(PLAYER, "later-session", oldTicket, oldPlayer));
        assertTrue(routes.permitRoute(PLAYER, "new-session", newTicket, newPlayer));
        routes.resetForCurrentSession(PLAYER, "new-session", newTicket, newPlayer);
        assertTrue(routes.permitRoute(PLAYER, "new-session", newTicket, newPlayer));
        assertEquals(VelocityDeferredDispositionRoutes.DeferResult.QUEUED,
                routes.defer(event(DispositionAction.LIMIT, "new-session"),
                        "limited", 9L, newTicket, newPlayer));
        assertEquals(newTicket, routes.claimForPostConnect(PLAYER, 9L, newTicket, newPlayer)
                .orElseThrow().loginTicket());
    }

    private static RoutesHarness routes(Instant now) {
        return new RoutesHarness(Clock.fixed(now, ZoneOffset.UTC));
    }

    private static final class RoutesHarness {
        private static final Object PLAYER_IDENTITY = new Object();
        private static final VelocityLoginLifecycle.LoginTicket LOGIN_TICKET =
                new VelocityLoginLifecycle.LoginTicket(101L);
        private final VelocityDeferredDispositionRoutes delegate;

        private RoutesHarness(Clock clock) {
            delegate = new VelocityDeferredDispositionRoutes(clock);
        }

        private VelocityDeferredDispositionRoutes.DeferResult defer(
                AuthenticatedManifestDispositionEvent event, String target, long generation) {
            return delegate.defer(event, target, generation, LOGIN_TICKET, PLAYER_IDENTITY);
        }

        private Optional<VelocityDeferredDispositionRoutes.Pending> claimForPostConnect(
                UUID playerId, long generation) {
            return delegate.claimForPostConnect(playerId, generation, LOGIN_TICKET, PLAYER_IDENTITY);
        }

        private void clear(UUID playerId) { delegate.clear(playerId); }
        private void clearSession(UUID playerId, String sessionId) {
            delegate.clearSession(playerId, sessionId, LOGIN_TICKET, PLAYER_IDENTITY);
        }
        private boolean permitRoute(UUID playerId, String sessionId) {
            return delegate.permitRoute(playerId, sessionId, LOGIN_TICKET, PLAYER_IDENTITY);
        }
        private void resetForCurrentSession(UUID playerId, String sessionId) {
            delegate.resetForCurrentSession(playerId, sessionId, LOGIN_TICKET, PLAYER_IDENTITY);
        }
        private VelocityDispositionExecutor.RouteOutcome executeIfPermitted(
                UUID playerId,
                String sessionId,
                java.util.function.Supplier<VelocityDispositionExecutor.RouteOutcome> operation) {
            return delegate.executeIfPermitted(
                    playerId, sessionId, LOGIN_TICKET, PLAYER_IDENTITY, operation);
        }
        private void markDenied(UUID playerId, String sessionId) {
            delegate.markDenied(playerId, sessionId, LOGIN_TICKET, PLAYER_IDENTITY);
        }
        private int pendingCount() { return delegate.pendingCount(); }
    }

    private static AuthenticatedManifestDispositionEvent event(DispositionAction action, String sessionId) {
        return event(PLAYER, action, sessionId);
    }

    private static AuthenticatedManifestDispositionEvent event(UUID player, DispositionAction action, String sessionId) {
        return new AuthenticatedManifestDispositionEvent(
                player, sessionId, NOW, action, Optional.of("rule-a"), ProxyPolicyRefreshStatus.ACTIVE,
                Optional.of("policy-a"), Optional.of(2L), Optional.of(NOW.plusSeconds(60)),
                ObservationOrigin.SERVER_CONFIRMED,
                Optional.of(UUID.fromString("00000000-0000-0000-0000-000000000099")),
                Optional.empty(), Optional.of("33".repeat(32)));
    }

    private static AuthenticatedManifestDispositionEvent expiredEvent() {
        return new AuthenticatedManifestDispositionEvent(
                PLAYER, "session-a", NOW, DispositionAction.LIMIT, Optional.of("rule-a"),
                ProxyPolicyRefreshStatus.ACTIVE, Optional.of("policy-a"), Optional.of(2L),
                Optional.of(NOW.minusSeconds(1)), ObservationOrigin.SERVER_CONFIRMED,
                Optional.of(UUID.fromString("00000000-0000-0000-0000-000000000099")),
                Optional.empty(), Optional.of("33".repeat(32)));
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) { this.instant = instant; }
        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return instant; }
        private void advance(Duration duration) { instant = instant.plus(duration); }
    }

    private static void await(CountDownLatch start, Runnable action) {
        try {
            assertTrue(start.await(1, TimeUnit.SECONDS));
            action.run();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AssertionError(exception);
        }
    }
}
