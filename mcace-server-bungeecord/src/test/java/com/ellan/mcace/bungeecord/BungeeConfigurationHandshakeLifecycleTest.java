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
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import net.md_5.bungee.api.event.PlayerConfigurationEvent;
import org.junit.jupiter.api.Test;

/**
 * Deterministic lifecycle coverage for the Bungee adapter's configuration-phase handshake gate.
 * These tests deliberately model identity/ticket transitions rather than needing a live proxy.
 */
final class BungeeConfigurationHandshakeLifecycleTest {
    private static final UUID PLAYER_ID = UUID.fromString("00000000-0000-0000-0000-000000000301");

    @Test
    void postLoginOnlyRetiresOldStateAndPublishesTicketWithoutBeginning() {
        BungeeDeferredDispositionRoutes routes = routes();
        Object predecessor = new Object();
        routes.beginLogin(PLAYER_ID, predecessor);
        RecordingBridge bridge = new RecordingBridge();
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges = new ConcurrentHashMap<>();

        BungeeDeferredDispositionRoutes.LoginTicket ticket = MCAceBungeePlugin.replacePhysicalLogin(
                routes, challenges, bridge, PLAYER_ID, new Object());

        assertEquals(0, bridge.begun, "PostLogin must never start or send the initial hello");
        assertEquals(1, bridge.removed, "the predecessor coordinator state is retired exactly once");
        assertFalse(MCAceBungeePlugin.isTicketBoundChallenge(challenges, PLAYER_ID, ticket),
                "only LOGIN configuration arms the challenge");
    }

    @Test
    void loginConfigurationStartsExactTicketOnceAndReconfigureIsInert() {
        BungeeDeferredDispositionRoutes routes = routes();
        Object player = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket ticket = routes.beginLogin(PLAYER_ID, player);
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges = new ConcurrentHashMap<>();
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> attempts = new ConcurrentHashMap<>();
        RecordingBridge bridge = new RecordingBridge();

        assertTrue(MCAceBungeePlugin.isInitialConfigurationReason(PlayerConfigurationEvent.Reason.LOGIN));
        assertFalse(MCAceBungeePlugin.isInitialConfigurationReason(PlayerConfigurationEvent.Reason.RECONFIGURE));
        assertTrue(MCAceBungeePlugin.mayStartConfigurationHandshake(challenges, attempts, PLAYER_ID, ticket));

        attempts.put(PLAYER_ID, ticket);
        assertTrue(MCAceBungeePlugin.installTicketBoundChallenge(challenges, PLAYER_ID, ticket));
        bridge.begin(PLAYER_ID);

        assertEquals(1, bridge.begun);
        assertTrue(MCAceBungeePlugin.isTicketBoundChallenge(challenges, PLAYER_ID, ticket));
        assertFalse(MCAceBungeePlugin.mayStartConfigurationHandshake(challenges, attempts, PLAYER_ID, ticket),
                "a duplicate LOGIN event cannot call begin a second time");
        assertEquals(1, bridge.begun);
    }

    @Test
    void staleReplacementAndOldDisconnectCannotAffectNewTicket() {
        BungeeDeferredDispositionRoutes routes = routes();
        Object formerPlayer = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket formerTicket = routes.beginLogin(PLAYER_ID, formerPlayer);
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges = new ConcurrentHashMap<>();
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> attempts = new ConcurrentHashMap<>();
        challenges.put(PLAYER_ID, formerTicket);
        attempts.put(PLAYER_ID, formerTicket);

        Object replacementPlayer = new Object();
        MCAceBungeePlugin.replaceTicketBoundChallenge(challenges, PLAYER_ID);
        MCAceBungeePlugin.replaceTicketBoundChallenge(attempts, PLAYER_ID);
        BungeeDeferredDispositionRoutes.LoginTicket replacementTicket = routes.beginLogin(PLAYER_ID, replacementPlayer);

        assertFalse(routes.isCurrent(PLAYER_ID, formerPlayer, formerTicket));
        assertTrue(routes.isCurrent(PLAYER_ID, replacementPlayer, replacementTicket));
        assertTrue(MCAceBungeePlugin.mayStartConfigurationHandshake(
                challenges, attempts, PLAYER_ID, replacementTicket));
        attempts.put(PLAYER_ID, replacementTicket);
        assertTrue(MCAceBungeePlugin.installTicketBoundChallenge(challenges, PLAYER_ID, replacementTicket));

        assertFalse(routes.clear(PLAYER_ID, formerPlayer, formerTicket),
                "late disconnect of the old physical player is inert");
        assertFalse(MCAceBungeePlugin.removeTicketBoundChallenge(challenges, PLAYER_ID, formerTicket));
        assertTrue(MCAceBungeePlugin.isTicketBoundChallenge(challenges, PLAYER_ID, replacementTicket));
    }

    @Test
    void emptyBeginRetiresBridgeWithoutArmingAndReplacementGetsNewOneShotTicket() {
        BungeeDeferredDispositionRoutes routes = routes();
        Object formerPlayer = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket formerTicket = routes.beginLogin(PLAYER_ID, formerPlayer);
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges = new ConcurrentHashMap<>();
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> attempts = new ConcurrentHashMap<>();
        RecordingBridge bridge = new RecordingBridge();

        attempts.put(PLAYER_ID, formerTicket);
        assertTrue(MCAceBungeePlugin.installTicketBoundChallenge(challenges, PLAYER_ID, formerTicket));
        assertEquals(Optional.empty(), MCAceBungeePlugin.retireUnsentConfigurationHandshake(
                challenges, bridge, PLAYER_ID, formerTicket));
        assertEquals(1, bridge.removed, "Optional.empty begin retires its exact coordinator state");
        assertFalse(MCAceBungeePlugin.isTicketBoundChallenge(challenges, PLAYER_ID, formerTicket),
                "Optional.empty begin must never leave inbound frame permission armed");
        assertFalse(MCAceBungeePlugin.mayStartConfigurationHandshake(challenges, attempts, PLAYER_ID, formerTicket),
                "the failed physical ticket remains one-shot and duplicate LOGIN is inert");

        Object replacementPlayer = new Object();
        MCAceBungeePlugin.replaceTicketBoundChallenge(attempts, PLAYER_ID);
        BungeeDeferredDispositionRoutes.LoginTicket replacementTicket = routes.beginLogin(PLAYER_ID, replacementPlayer);
        assertTrue(MCAceBungeePlugin.mayStartConfigurationHandshake(
                challenges, attempts, PLAYER_ID, replacementTicket),
                "only an exact replacement retirement may authorize a fresh ticket");
    }

    @Test
    void strictBeginFailureRetiresAttemptAndRecordsTerminalPhysicalDeny() {
        BungeeDeferredDispositionRoutes routes = routes();
        Object player = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket ticket = routes.beginLogin(PLAYER_ID, player);
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges = new ConcurrentHashMap<>();
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> attempts = new ConcurrentHashMap<>();
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> terminalTickets = new ConcurrentHashMap<>();
        RecordingBridge bridge = new RecordingBridge();
        attempts.put(PLAYER_ID, ticket);

        assertEquals(Optional.empty(), MCAceBungeePlugin.retireFailedConfigurationHandshake(
                challenges, attempts, terminalTickets, bridge, PLAYER_ID, ticket));
        assertFalse(challenges.containsKey(PLAYER_ID));
        assertFalse(attempts.containsKey(PLAYER_ID));
        assertEquals(ticket, terminalTickets.get(PLAYER_ID));
        assertEquals(1, bridge.removed, "strict begin failure retires bridge state once");
        assertFalse(MCAceBungeePlugin.mayStartConfigurationHandshake(
                challenges, attempts, terminalTickets, PLAYER_ID, ticket));

        assertTrue(routes.markDeniedPhysical(PLAYER_ID, player, ticket));
        assertFalse(routes.permitRoute(PLAYER_ID, "pre-auth", player, ticket));
    }

    @Test
    void strictSendFailureRetiresArmedChallengeAndLeavesLateFrameInert() {
        BungeeDeferredDispositionRoutes routes = routes();
        Object player = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket ticket = routes.beginLogin(PLAYER_ID, player);
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges = new ConcurrentHashMap<>();
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> attempts = new ConcurrentHashMap<>();
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> terminalTickets = new ConcurrentHashMap<>();
        RecordingBridge bridge = new RecordingBridge();
        attempts.put(PLAYER_ID, ticket);
        assertTrue(MCAceBungeePlugin.installTicketBoundChallenge(challenges, PLAYER_ID, ticket));

        MCAceBungeePlugin.retireFailedConfigurationHandshake(
                challenges, attempts, terminalTickets, bridge, PLAYER_ID, ticket);

        assertFalse(MCAceBungeePlugin.isTicketBoundChallenge(challenges, PLAYER_ID, ticket),
                "strict send failure revokes inbound configuration permission");
        assertFalse(MCAceBungeePlugin.mayProcessConfigurationBoundFrame(
                true, challenges, PLAYER_ID, ticket),
                "a late frame after strict send failure cannot reach the bridge");
        assertEquals(ticket, terminalTickets.get(PLAYER_ID));
        assertFalse(MCAceBungeePlugin.mayStartConfigurationHandshake(
                challenges, attempts, terminalTickets, PLAYER_ID, ticket));
    }

    @Test
    void terminalTimeoutCleanupIsExactTicketBound() {
        BungeeDeferredDispositionRoutes routes = routes();
        Object formerPlayer = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket formerTicket = routes.beginLogin(PLAYER_ID, formerPlayer);
        Object currentPlayer = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket currentTicket = routes.beginLogin(PLAYER_ID, currentPlayer);
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges = new ConcurrentHashMap<>();
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> attempts = new ConcurrentHashMap<>();
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> terminalTickets = new ConcurrentHashMap<>();
        challenges.put(PLAYER_ID, currentTicket);
        attempts.put(PLAYER_ID, currentTicket);

        assertFalse(MCAceBungeePlugin.retireTerminalConfigurationTicket(
                challenges, attempts, terminalTickets, PLAYER_ID, formerTicket));
        assertTrue(MCAceBungeePlugin.isTicketBoundChallenge(challenges, PLAYER_ID, currentTicket));
        assertTrue(MCAceBungeePlugin.retireTerminalConfigurationTicket(
                challenges, attempts, terminalTickets, PLAYER_ID, currentTicket));
        assertFalse(MCAceBungeePlugin.isTicketBoundChallenge(challenges, PLAYER_ID, currentTicket));
        assertFalse(attempts.containsKey(PLAYER_ID),
                "timeout clears the configurationStartAttempts entry for the terminal ticket");
        assertEquals(currentTicket, terminalTickets.get(PLAYER_ID),
                "a ticket-local terminal marker preserves no-retry after clearing both active maps");
        assertFalse(MCAceBungeePlugin.mayStartConfigurationHandshake(
                challenges, attempts, terminalTickets, PLAYER_ID, currentTicket),
                "the same physical timeout remains terminal rather than creating a second begin");
    }

    @Test
    void sendFailureRemainsInertUntilExactPhysicalLoginRetires() {
        BungeeDeferredDispositionRoutes routes = routes();
        Object player = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket ticket = routes.beginLogin(PLAYER_ID, player);
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges = new ConcurrentHashMap<>();
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> attempts = new ConcurrentHashMap<>();

        // begin() was attempted but player.sendData failed: inbound frames lose their challenge
        // permission and a duplicate LOGIN event cannot retry the now-terminal ticket.
        attempts.put(PLAYER_ID, ticket);
        assertTrue(MCAceBungeePlugin.installTicketBoundChallenge(challenges, PLAYER_ID, ticket));
        assertTrue(MCAceBungeePlugin.removeTicketBoundChallenge(challenges, PLAYER_ID, ticket));
        assertFalse(MCAceBungeePlugin.isTicketBoundChallenge(challenges, PLAYER_ID, ticket));
        assertFalse(MCAceBungeePlugin.mayStartConfigurationHandshake(challenges, attempts, PLAYER_ID, ticket));
        assertTrue(routes.clear(PLAYER_ID, player, ticket));
        assertTrue(MCAceBungeePlugin.removeTicketBoundChallenge(attempts, PLAYER_ID, ticket));
        assertFalse(routes.ticketFor(PLAYER_ID, player).isPresent(),
                "the exact disconnect is the only lifecycle event that retires the attempt marker");
    }

    @Test
    void serverConnectedDoesNotStartAndUnarmedPluginFrameCannotReachBridge() {
        BungeeDeferredDispositionRoutes routes = routes();
        Object player = new Object();
        BungeeDeferredDispositionRoutes.LoginTicket ticket = routes.beginLogin(PLAYER_ID, player);
        Map<UUID, BungeeDeferredDispositionRoutes.LoginTicket> challenges = new ConcurrentHashMap<>();
        RecordingBridge bridge = new RecordingBridge();

        assertTrue(routes.markBackendReady(PLAYER_ID, player).isPresent());
        assertEquals(0, bridge.begun, "ServerConnected only marks a backend ready; it never starts hello");
        assertFalse(MCAceBungeePlugin.isTicketBoundChallenge(challenges, PLAYER_ID, ticket));
        assertFalse(MCAceBungeePlugin.mayProcessConfigurationBoundFrame(
                true, challenges, PLAYER_ID, ticket));
        assertEquals(0, bridge.received,
                "without the exact configuration-armed challenge, PluginMessage must be inert");
    }

    private static BungeeDeferredDispositionRoutes routes() {
        return new BungeeDeferredDispositionRoutes(
                Clock.fixed(Instant.parse("2026-08-09T00:00:00Z"), ZoneOffset.UTC));
    }

    private static final class RecordingBridge implements BungeeSessionBridge {
        private final InMemoryMCAceApi api = new InMemoryMCAceApi();
        private int begun;
        private int received;
        private int removed;

        @Override
        public Optional<byte[]> begin(UUID playerId) {
            begun++;
            return Optional.empty();
        }

        @Override
        public BungeeBridgeAction receive(UUID playerId, byte[] encodedFrame) {
            received++;
            return BungeeBridgeAction.none();
        }

        @Override
        public List<PlayerSecuritySnapshot> expireTimedOut() {
            return List.of();
        }

        @Override
        public void remove(UUID playerId) {
            removed++;
        }

        @Override
        public MCAceApi api() {
            return api;
        }
    }
}
