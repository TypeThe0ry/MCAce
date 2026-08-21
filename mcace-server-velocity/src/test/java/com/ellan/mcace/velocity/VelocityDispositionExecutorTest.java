package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent;
import com.ellan.mcace.core.proxy.ProxyPolicyRefreshStatus;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class VelocityDispositionExecutorTest {
    private static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final Instant NOW = Instant.parse("2026-08-09T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void noticeAndWarnSendOnlyContentFreeMessagesOnce() {
        FakeActions actions = new FakeActions();
        VelocityDispositionExecutor executor = new VelocityDispositionExecutor(
                VelocityAdmissionConfig.Mode.LIMITED_ROUTE, actions, CLOCK, ignored -> true);

        assertEquals(VelocityDispositionExecutor.Status.NOTICE_SENT,
                executor.apply(event(DispositionAction.NOTICE, "notice-session")).status());
        VelocityDispositionExecutor.Result first = executor.apply(event(DispositionAction.WARN));
        VelocityDispositionExecutor.Result duplicate = executor.apply(event(DispositionAction.WARN));

        assertEquals(VelocityDispositionExecutor.Status.WARN_SENT, first.status());
        assertEquals(VelocityDispositionExecutor.Status.DUPLICATE, duplicate.status());
        assertEquals(2, actions.messages.size());
        for (String message : actions.messages) {
            assertFalse(message.contains("/") || message.contains("sha256") || message.contains("rule"));
        }
    }

    @Test
    void lateSessionEventsAreDroppedBeforeAnyPlayerMessageOrAdmissionAction() {
        FakeActions actions = new FakeActions();
        actions.current = false;
        VelocityDispositionExecutor executor = new VelocityDispositionExecutor(
                VelocityAdmissionConfig.Mode.LIMITED_ROUTE, actions, CLOCK, ignored -> true);

        assertEquals(VelocityDispositionExecutor.Status.STALE_SESSION,
                executor.apply(event(DispositionAction.WARN)).status());
        assertEquals(VelocityDispositionExecutor.Status.STALE_SESSION,
                executor.apply(event(DispositionAction.DENY)).status());
        assertTrue(actions.messages.isEmpty());
        assertTrue(actions.routes.isEmpty());
        assertFalse(actions.denied);
    }

    @Test
    void invalidPolicyAndBaselineAnomalyCannotExecuteOrBeOverridden() {
        FakeActions actions = new FakeActions();
        VelocityDispositionExecutor executor = new VelocityDispositionExecutor(
                VelocityAdmissionConfig.Mode.LIMITED_ROUTE, actions, CLOCK, ignored -> true);

        assertEquals(VelocityDispositionExecutor.Status.NO_VALID_POLICY,
                executor.apply(event(DispositionAction.DENY, ProxyPolicyRefreshStatus.REJECTED_INVALID)).status());
        actions.verified = false;
        assertEquals(VelocityDispositionExecutor.Status.BASELINE_PROTECTED,
                executor.apply(event(DispositionAction.DENY)).status());
        assertFalse(actions.denied);
    }

    @Test
    void limitAndQuarantineUseIndependentRoutesButDenyOnlyDisconnectsAndNeverBans() {
        FakeActions actions = new FakeActions();
        VelocityDispositionExecutor executor = new VelocityDispositionExecutor(
                VelocityAdmissionConfig.Mode.LIMITED_ROUTE, actions, CLOCK, ignored -> true);

        assertEquals(VelocityDispositionExecutor.Status.LIMITED_DISPATCHED,
                executor.apply(event(DispositionAction.LIMIT, "limit-session")).status());
        executor.clear(PLAYER);
        assertEquals(VelocityDispositionExecutor.Status.QUARANTINED_DISPATCHED,
                executor.apply(event(DispositionAction.QUARANTINE, "quarantine-session")).status());
        executor.clear(PLAYER);
        assertEquals(VelocityDispositionExecutor.Status.DENIED,
                executor.apply(event(DispositionAction.DENY, "deny-session")).status());
        assertEquals(List.of("limited", "quarantine"), actions.routes);
        assertTrue(actions.denied);
        assertFalse(actions.banned);
    }

    @Test
    void configurationStageRouteIsExplicitlyDeferredRatherThanReportedAsDispatched() {
        FakeActions actions = new FakeActions();
        actions.routeOutcome = VelocityDispositionExecutor.RouteOutcome.DEFERRED;
        VelocityDispositionExecutor executor = new VelocityDispositionExecutor(
                VelocityAdmissionConfig.Mode.LIMITED_ROUTE, actions, CLOCK, ignored -> true);

        assertEquals(VelocityDispositionExecutor.Status.DEFERRED_ROUTE,
                executor.apply(event(DispositionAction.LIMIT, "configuration-session")).status());
        assertTrue(actions.routes.isEmpty());
        actions.routeOutcome = VelocityDispositionExecutor.RouteOutcome.DISPATCHED;
        assertEquals(VelocityDispositionExecutor.Status.LIMITED_DISPATCHED,
                executor.apply(event(DispositionAction.LIMIT, "configuration-session")).status());
        assertEquals(List.of("limited"), actions.routes);
    }

    @Test
    void monitorModeLeavesHighActionsUnenforced() {
        FakeActions actions = new FakeActions();
        VelocityDispositionExecutor executor = new VelocityDispositionExecutor(
                VelocityAdmissionConfig.Mode.MONITOR, actions, CLOCK, ignored -> true);

        assertEquals(VelocityDispositionExecutor.Status.NOT_ENFORCED,
                executor.apply(event(DispositionAction.LIMIT, "monitor-limit")).status());
        assertEquals(VelocityDispositionExecutor.Status.NOT_ENFORCED,
                executor.apply(event(DispositionAction.QUARANTINE, "monitor-quarantine")).status());
        assertEquals(VelocityDispositionExecutor.Status.NOT_ENFORCED,
                executor.apply(event(DispositionAction.DENY)).status());
        assertTrue(actions.routes.isEmpty());
        assertFalse(actions.denied);
    }

    @Test
    void expiredSignedEventDoesNotReachAPlayer() {
        FakeActions actions = new FakeActions();
        VelocityDispositionExecutor executor = new VelocityDispositionExecutor(
                VelocityAdmissionConfig.Mode.LIMITED_ROUTE, actions,
                Clock.fixed(NOW.plusSeconds(61), ZoneOffset.UTC), ignored -> true);

        assertEquals(VelocityDispositionExecutor.Status.NO_VALID_POLICY,
                executor.apply(event(DispositionAction.WARN)).status());
        assertTrue(actions.messages.isEmpty());
    }

    @Test
    void supersededPolicyIsRecheckedAtExecutionTime() {
        FakeActions actions = new FakeActions();
        VelocityDispositionExecutor executor = new VelocityDispositionExecutor(
                VelocityAdmissionConfig.Mode.LIMITED_ROUTE, actions, CLOCK, ignored -> false);

        assertEquals(VelocityDispositionExecutor.Status.NO_VALID_POLICY,
                executor.apply(event(DispositionAction.DENY)).status());
        assertFalse(actions.denied);
        assertTrue(actions.routes.isEmpty());
        assertTrue(actions.messages.isEmpty());
    }

    @Test
    void staleAuthorizationContextCannotExecuteAHighImpactAction() {
        FakeActions actions = new FakeActions();
        actions.currentAuthorizationContext = false;
        VelocityDispositionExecutor executor = new VelocityDispositionExecutor(
                VelocityAdmissionConfig.Mode.LIMITED_ROUTE, actions, CLOCK, ignored -> true);

        assertEquals(VelocityDispositionExecutor.Status.STALE_AUTHORIZATION_CONTEXT,
                executor.apply(event(DispositionAction.DENY)).status());
        assertTrue(actions.messages.isEmpty());
        assertTrue(actions.routes.isEmpty());
        assertFalse(actions.denied);
    }

    @Test
    void clearingOneSessionCannotEraseADelimiterPrefixedReplacementSession() {
        FakeActions actions = new FakeActions();
        VelocityDispositionExecutor executor = new VelocityDispositionExecutor(
                VelocityAdmissionConfig.Mode.LIMITED_ROUTE, actions, CLOCK, ignored -> true);
        AuthenticatedManifestDispositionEvent replacement =
                event(DispositionAction.WARN, "session|replacement");

        assertEquals(VelocityDispositionExecutor.Status.WARN_SENT,
                executor.apply(replacement).status());
        executor.clearSession(PLAYER, "session");
        assertEquals(VelocityDispositionExecutor.Status.DUPLICATE,
                executor.apply(replacement).status());
        assertEquals(1, actions.messages.size());
    }

    @Test
    void independentTrustedAuthorizationsAreNotCollapsedAsDuplicates() {
        FakeActions actions = new FakeActions();
        VelocityDispositionExecutor executor = new VelocityDispositionExecutor(
                VelocityAdmissionConfig.Mode.LIMITED_ROUTE, actions, CLOCK, ignored -> true);
        AuthenticatedManifestDispositionEvent first = event(DispositionAction.WARN);
        AuthenticatedManifestDispositionEvent second = new AuthenticatedManifestDispositionEvent(
                first.playerId(), first.sessionId(), first.evaluatedAt(), first.highestAction(),
                first.winningRuleId(), first.refreshStatus(), first.activePolicyVersion(),
                first.activePolicySequence(), first.activePolicyExpiresAt(), first.authorityOrigin(),
                Optional.of(UUID.fromString("00000000-0000-0000-0000-000000000100")),
                first.reviewTicket(), Optional.of("44".repeat(32)));

        assertEquals(VelocityDispositionExecutor.Status.WARN_SENT, executor.apply(first).status());
        assertEquals(VelocityDispositionExecutor.Status.WARN_SENT, executor.apply(second).status());
        assertEquals(2, actions.messages.size());
    }

    @Test
    void fullIdempotencyCapacityFailsClosedButExactSessionCleanupReleasesIt() {
        FakeActions actions = new FakeActions();
        VelocityDispositionExecutor executor = new VelocityDispositionExecutor(
                VelocityAdmissionConfig.Mode.LIMITED_ROUTE, actions, CLOCK, ignored -> true);
        AuthenticatedManifestDispositionEvent first = null;
        for (int index = 0; index < 4_096; index++) {
            AuthenticatedManifestDispositionEvent candidate = eventWithAuthorization(
                    "capacity-session", new UUID(1L, index + 1L));
            if (index == 0) first = candidate;
            assertEquals(VelocityDispositionExecutor.Status.WARN_SENT,
                    executor.apply(candidate).status());
        }

        assertEquals(VelocityDispositionExecutor.Status.ACTION_UNAVAILABLE,
                executor.apply(eventWithAuthorization(
                        "capacity-session", new UUID(2L, 1L))).status());
        assertEquals(VelocityDispositionExecutor.Status.DUPLICATE,
                executor.apply(first).status());
        assertEquals(4_096, actions.messages.size());

        executor.clearSession(PLAYER, "capacity-session");
        assertEquals(VelocityDispositionExecutor.Status.WARN_SENT,
                executor.apply(eventWithAuthorization(
                        "capacity-session", new UUID(2L, 2L))).status());
        assertEquals(4_097, actions.messages.size());
    }

    private static AuthenticatedManifestDispositionEvent event(DispositionAction action) {
        return event(action, "session-a");
    }

    private static AuthenticatedManifestDispositionEvent event(
            DispositionAction action, String sessionId) {
        return event(action, sessionId, ProxyPolicyRefreshStatus.ACTIVE);
    }

    private static AuthenticatedManifestDispositionEvent event(
            DispositionAction action, ProxyPolicyRefreshStatus status) {
        return event(action, "session-a", status);
    }

    private static AuthenticatedManifestDispositionEvent event(
            DispositionAction action, String sessionId, ProxyPolicyRefreshStatus status) {
        return new AuthenticatedManifestDispositionEvent(
                PLAYER, sessionId, NOW, action, Optional.of("rule-a"), status,
                status == ProxyPolicyRefreshStatus.ACTIVE ? Optional.of("policy-a") : Optional.empty(),
                status == ProxyPolicyRefreshStatus.ACTIVE ? Optional.of(2L) : Optional.empty(),
                status == ProxyPolicyRefreshStatus.ACTIVE ? Optional.of(NOW.plusSeconds(60)) : Optional.empty(),
                ObservationOrigin.SERVER_CONFIRMED,
                Optional.of(UUID.fromString("00000000-0000-0000-0000-000000000099")),
                Optional.empty(), Optional.of("33".repeat(32)));
    }

    private static AuthenticatedManifestDispositionEvent eventWithAuthorization(
            String sessionId, UUID authorizationId) {
        return new AuthenticatedManifestDispositionEvent(
                PLAYER, sessionId, NOW, DispositionAction.WARN, Optional.of("rule-a"),
                ProxyPolicyRefreshStatus.ACTIVE, Optional.of("policy-a"), Optional.of(2L),
                Optional.of(NOW.plusSeconds(60)), ObservationOrigin.SERVER_CONFIRMED,
                Optional.of(authorizationId), Optional.empty(), Optional.of("55".repeat(32)));
    }

    private static final class FakeActions implements VelocityDispositionExecutor.Actions {
        private boolean current = true;
        private boolean verified = true;
        private boolean currentAuthorizationContext = true;
        private boolean denied;
        private boolean banned;
        private VelocityDispositionExecutor.RouteOutcome routeOutcome =
                VelocityDispositionExecutor.RouteOutcome.DISPATCHED;
        private final List<String> messages = new ArrayList<>();
        private final List<String> routes = new ArrayList<>();

        @Override public boolean isCurrentAuthenticatedSession(UUID playerId, String sessionId) { return current; }
        @Override public boolean isVerifiedAdmission(UUID playerId) { return verified; }
        @Override public boolean isCurrentAuthorizationContext(
                AuthenticatedManifestDispositionEvent event) { return currentAuthorizationContext; }
        @Override public boolean sendMessage(UUID playerId, String sessionId, String message) {
            messages.add(message);
            return true;
        }
        @Override public VelocityDispositionExecutor.RouteOutcome routeToLimited(UUID playerId, String sessionId) {
            if (routeOutcome == VelocityDispositionExecutor.RouteOutcome.DISPATCHED) routes.add("limited");
            return routeOutcome;
        }
        @Override public VelocityDispositionExecutor.RouteOutcome routeToQuarantine(UUID playerId, String sessionId) {
            if (routeOutcome == VelocityDispositionExecutor.RouteOutcome.DISPATCHED) routes.add("quarantine");
            return routeOutcome;
        }
        @Override public boolean deny(UUID playerId, String sessionId, String message) { denied = true; return true; }
    }
}
