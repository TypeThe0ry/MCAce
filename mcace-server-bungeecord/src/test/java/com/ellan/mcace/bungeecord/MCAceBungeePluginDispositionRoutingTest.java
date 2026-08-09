package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.sdk.MCAceApi;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

final class MCAceBungeePluginDispositionRoutingTest {
    @Test
    void invalidLimitedRouteConfigurationDowngradesOnlyHighImpactExecution() {
        Optional<BungeeDispositionRouteTargets> unresolved = MCAceBungeePlugin.resolveDispositionRouteTargets(
                BungeeDispositionExecutionMode.LIMITED_ROUTE, Optional.of("limited"), Optional.empty(),
                Set.of("limited", "quarantine"));

        assertEquals(Optional.empty(), unresolved);
        assertEquals(BungeeDispositionExecutionMode.MONITOR,
                MCAceBungeePlugin.effectiveDispositionExecutionMode(
                        BungeeDispositionExecutionMode.LIMITED_ROUTE, unresolved));
    }

    @Test
    void registeredDistinctRouteTargetsKeepLimitedRouteEnabled() {
        Optional<BungeeDispositionRouteTargets> resolved = MCAceBungeePlugin.resolveDispositionRouteTargets(
                BungeeDispositionExecutionMode.LIMITED_ROUTE, Optional.of("limited"),
                Optional.of("quarantine"), Set.of("limited", "quarantine"));

        assertTrue(resolved.isPresent());
        assertEquals(BungeeDispositionExecutionMode.LIMITED_ROUTE,
                MCAceBungeePlugin.effectiveDispositionExecutionMode(
                        BungeeDispositionExecutionMode.LIMITED_ROUTE, resolved));
    }

    @Test
    void replacementLoginClearsOnlyItsPredecessorChallengeAndOldLifecycleCannotConsumeNewTicket() {
        var routes = new BungeeDeferredDispositionRoutes(
                Clock.fixed(Instant.parse("2026-08-09T00:00:00Z"), ZoneOffset.UTC));
        var playerId = java.util.UUID.fromString("00000000-0000-0000-0000-000000000201");
        Object oldPhysicalPlayer = new Object();
        var oldTicket = routes.beginLogin(playerId, oldPhysicalPlayer);
        Map<java.util.UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges =
                new java.util.concurrent.ConcurrentHashMap<>();
        assertTrue(MCAceBungeePlugin.installTicketBoundChallenge(challenges, playerId, oldTicket));
        RecordingBridge bridge = new RecordingBridge();
        bridge.begin(playerId); // Old PostLogin/authentication has already created bridge state.

        // This is the lifecycle-locked portion of a new PostLogin before its new delayed start.
        // It removes the predecessor bridge exactly once, clears only the predecessor challenge,
        // and publishes a distinct physical-login ticket.
        Object newPhysicalPlayer = new Object();
        var newTicket = MCAceBungeePlugin.replacePhysicalLogin(
                routes, challenges, bridge, playerId, newPhysicalPlayer);
        assertEquals(1, bridge.removed, "new PostLogin removes the exact predecessor bridge once");
        assertTrue(MCAceBungeePlugin.installTicketBoundChallenge(challenges, playerId, newTicket));
        bridge.begin(playerId); // New delayed start consumes its own ticket and begins normally.
        assertEquals(2, bridge.begun);
        assertFalse(MCAceBungeePlugin.removeTicketBoundChallenge(challenges, playerId, oldTicket));
        assertEquals(newTicket, challenges.get(playerId));
        assertFalse(routes.isCurrent(playerId, oldPhysicalPlayer, oldTicket));
        assertTrue(routes.isCurrent(playerId, newPhysicalPlayer, newTicket));
        assertFalse(routes.clear(playerId, oldPhysicalPlayer, oldTicket),
                "late old disconnect cannot clear the new physical login");
        assertEquals(1, bridge.removed, "late old disconnect is inert and cannot remove new bridge state");
    }

    @Test
    void routeCompletionCallbackIsConsumedOnceAndAFormerLoginCannotPassTheNewTicketGate() {
        AtomicBoolean completion = new AtomicBoolean();
        assertTrue(MCAceBungeePlugin.consumeRouteCompletion(completion));
        assertFalse(MCAceBungeePlugin.consumeRouteCompletion(completion));
        assertTrue(MCAceBungeePlugin.successfulRouteCompletion(Boolean.TRUE, null));
        assertFalse(MCAceBungeePlugin.successfulRouteCompletion(Boolean.FALSE, null));
        assertFalse(MCAceBungeePlugin.successfulRouteCompletion(null, null));
        assertFalse(MCAceBungeePlugin.successfulRouteCompletion(Boolean.TRUE, new IllegalStateException("callback error")));

        var routes = new BungeeDeferredDispositionRoutes(
                Clock.fixed(Instant.parse("2026-08-09T00:00:00Z"), ZoneOffset.UTC));
        var playerId = java.util.UUID.fromString("00000000-0000-0000-0000-000000000202");
        Object formerPlayer = new Object();
        var formerTicket = routes.beginLogin(playerId, formerPlayer);
        Object replacementPlayer = new Object();
        var replacementTicket = routes.beginLogin(playerId, replacementPlayer);
        assertFalse(routes.isCurrent(playerId, formerPlayer, formerTicket),
                "a late former connect callback is ignored before it can report or mutate state");
        assertTrue(routes.isCurrent(playerId, replacementPlayer, replacementTicket));
    }

    @Test
    void exactFederationSessionIsRevokedBeforeCoordinatorRemoval() {
        List<String> calls = new java.util.ArrayList<>();
        MCAceBungeePlugin.removeFederationSessionThenBridge(
                Optional.of("exact-authenticated-session"),
                sessionId -> calls.add("federation:" + sessionId),
                () -> calls.add("bridge:remove"));

        assertEquals(List.of("federation:exact-authenticated-session", "bridge:remove"), calls,
                "a replacement must revoke the exact federation session before coordinator removal");
    }

    private static final class RecordingBridge implements BungeeSessionBridge {
        private final InMemoryMCAceApi api = new InMemoryMCAceApi();
        private int begun;
        private int removed;

        @Override
        public Optional<byte[]> begin(java.util.UUID playerId) {
            begun++;
            return Optional.empty();
        }

        @Override
        public BungeeBridgeAction receive(java.util.UUID playerId, byte[] encodedFrame) {
            return BungeeBridgeAction.none();
        }

        @Override
        public List<PlayerSecuritySnapshot> expireTimedOut() {
            return List.of();
        }

        @Override
        public void remove(java.util.UUID playerId) {
            removed++;
        }

        @Override
        public MCAceApi api() {
            return api;
        }
    }
}
