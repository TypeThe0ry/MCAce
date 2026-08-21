package com.ellan.mcace.bungeecord;

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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class BungeeDispositionExecutorTest {
    private static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final Instant NOW = Instant.parse("2026-08-09T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void auditWorkerOnlyQueuesAndSchedulerLaneSendsFixedMessagesOnce() {
        FakeActions actions = new FakeActions();
        List<Runnable> scheduled = new ArrayList<>();
        BungeeDispositionExecutor executor = executor(BungeeDispositionExecutionMode.MONITOR, actions, scheduled);

        assertTrue(executor.offer(event(DispositionAction.NOTICE, "notice-session")));
        assertTrue(actions.messages.isEmpty());
        assertEquals(1, scheduled.size());
        scheduled.removeFirst().run();
        assertEquals(BungeeDispositionExecutor.Status.NOTICE_SENT,
                executor.apply(event(DispositionAction.NOTICE, "other-session")).status());
        assertEquals(BungeeDispositionExecutor.Status.DUPLICATE,
                executor.apply(event(DispositionAction.NOTICE, "other-session")).status());
        assertEquals(2, actions.messages.size());
        for (String message : actions.messages) {
            assertFalse(message.contains("/") || message.contains("sha256") || message.contains("rule"));
        }
        assertTrue(actions.routeTargets.isEmpty(), "NOTICE must not route a player");
        assertEquals(BungeeDispositionExecutor.Status.WARN_SENT,
                executor.apply(event(DispositionAction.WARN, "warn-session")).status());
        assertTrue(actions.routeTargets.isEmpty(), "WARN must not route a player");
    }

    @Test
    void staleInvalidAndUnverifiedEventsCannotTouchPlayer() {
        FakeActions actions = new FakeActions();
        BungeeDispositionExecutor executor = executor(BungeeDispositionExecutionMode.LIMITED_ROUTE, actions, new ArrayList<>());

        actions.current = false;
        assertEquals(BungeeDispositionExecutor.Status.STALE_SESSION,
                executor.apply(event(DispositionAction.DENY)).status());
        actions.current = true;
        assertEquals(BungeeDispositionExecutor.Status.NO_VALID_POLICY,
                executor.apply(event(DispositionAction.DENY, ProxyPolicyRefreshStatus.REJECTED_INVALID)).status());
        actions.verified = false;
        assertEquals(BungeeDispositionExecutor.Status.BASELINE_PROTECTED,
                executor.apply(event(DispositionAction.DENY)).status());
        assertTrue(actions.messages.isEmpty());
        assertFalse(actions.denied);
    }

    @Test
    void monitorLeavesHighImpactActionsUnenforcedAndLimitedModeRoutesToSeparateTargets() {
        FakeActions monitorActions = new FakeActions();
        BungeeDispositionExecutor monitor = executor(
                BungeeDispositionExecutionMode.MONITOR, monitorActions, new ArrayList<>());
        assertEquals(BungeeDispositionExecutor.Status.NOT_ENFORCED,
                monitor.apply(event(DispositionAction.DENY)).status());
        assertFalse(monitorActions.denied);

        FakeActions limitedActions = new FakeActions();
        BungeeDispositionExecutor limited = executor(
                BungeeDispositionExecutionMode.LIMITED_ROUTE, limitedActions, new ArrayList<>());
        assertEquals(BungeeDispositionExecutor.Status.LIMITED_DISPATCHED,
                limited.apply(event(DispositionAction.LIMIT, "limit-session")).status());
        limited.clear(PLAYER, "limit-session");
        assertEquals(BungeeDispositionExecutor.Status.QUARANTINED_DISPATCHED,
                limited.apply(event(DispositionAction.QUARANTINE, "quarantine-session")).status());
        limited.clear(PLAYER, "quarantine-session");
        assertEquals(BungeeDispositionExecutor.Status.DENIED,
                limited.apply(event(DispositionAction.DENY, "deny-session")).status());
        assertEquals(List.of("limited", "quarantine"), limitedActions.routeTargets);
        assertTrue(limitedActions.denied);
        assertFalse(limitedActions.banned);
    }

    @Test
    void initialBackendDeferralIsAnAppliedOneShotRatherThanAClaimedSuccessfulConnection() {
        FakeActions actions = new FakeActions();
        actions.routeOutcome = BungeeDispositionExecutor.Actions.RouteOutcome.DEFERRED;
        BungeeDispositionExecutor executor = executor(
                BungeeDispositionExecutionMode.LIMITED_ROUTE, actions, new ArrayList<>());

        assertEquals(BungeeDispositionExecutor.Status.LIMITED_DEFERRED,
                executor.apply(event(DispositionAction.LIMIT, "initial-session")).status());
        assertEquals(BungeeDispositionExecutor.Status.DUPLICATE,
                executor.apply(event(DispositionAction.LIMIT, "initial-session")).status());
        assertEquals(List.of("limited"), actions.routeTargets);

        executor.clear(PLAYER, "initial-session");
        actions.routeOutcome = BungeeDispositionExecutor.Actions.RouteOutcome.UNAVAILABLE;
        assertEquals(BungeeDispositionExecutor.Status.ACTION_UNAVAILABLE,
                executor.apply(event(DispositionAction.QUARANTINE, "gone-session")).status());
    }

    @Test
    void missingWinnerIsIncompleteAndDisconnectClearsQueuedEvents() {
        FakeActions actions = new FakeActions();
        List<Runnable> scheduled = new ArrayList<>();
        BungeeDispositionExecutor executor = executor(BungeeDispositionExecutionMode.LIMITED_ROUTE, actions, scheduled);
        assertEquals(BungeeDispositionExecutor.Status.INCOMPLETE_EVENT,
                executor.apply(eventWithoutWinner()).status());
        assertTrue(executor.offer(event(DispositionAction.WARN)));
        executor.clear(PLAYER, "session-a");
        scheduled.removeFirst().run();
        assertTrue(actions.messages.isEmpty());
    }

    @Test
    void exactCleanupDoesNotTreatDelimiterBearingReplacementSessionAsAPrefix() {
        FakeActions actions = new FakeActions();
        BungeeDispositionExecutor executor = executor(
                BungeeDispositionExecutionMode.MONITOR, actions, new ArrayList<>());

        // Each action is a separate existing idempotency key for the same physical session.
        assertEquals(BungeeDispositionExecutor.Status.WARN_SENT,
                executor.apply(event(DispositionAction.WARN, "a")).status());
        assertEquals(BungeeDispositionExecutor.Status.NOTICE_SENT,
                executor.apply(event(DispositionAction.NOTICE, "a")).status());
        assertEquals(BungeeDispositionExecutor.Status.WARN_SENT,
                executor.apply(event(DispositionAction.WARN, "a|replacement")).status());
        assertEquals(BungeeDispositionExecutor.Status.NOTICE_SENT,
                executor.apply(event(DispositionAction.NOTICE, "a|replacement")).status());

        executor.clear(PLAYER, "a");

        // Clearing a departing session removes every one of its own idempotency keys.
        assertEquals(BungeeDispositionExecutor.Status.WARN_SENT,
                executor.apply(event(DispositionAction.WARN, "a")).status());
        assertEquals(BungeeDispositionExecutor.Status.NOTICE_SENT,
                executor.apply(event(DispositionAction.NOTICE, "a")).status());
        // It must not clear a legal replacement whose raw session id happens to share a prefix.
        assertEquals(BungeeDispositionExecutor.Status.DUPLICATE,
                executor.apply(event(DispositionAction.WARN, "a|replacement")).status());
        assertEquals(BungeeDispositionExecutor.Status.DUPLICATE,
                executor.apply(event(DispositionAction.NOTICE, "a|replacement")).status());
    }

    @Test
    void handoffQueueIsBoundedAndCloseDropsPendingEvents() {
        FakeActions actions = new FakeActions();
        List<Runnable> scheduled = new ArrayList<>();
        BungeeDispositionExecutor executor = new BungeeDispositionExecutor(
                BungeeDispositionExecutionMode.MONITOR, targets(), 1, scheduled::add, actions, CLOCK,
                ignored -> true, (ignored, result) -> { });

        assertTrue(executor.offer(event(DispositionAction.WARN)));
        assertFalse(executor.offer(event(DispositionAction.NOTICE, "second-session")));
        executor.close();
        assertTrue(scheduled.size() == 1);
        scheduled.removeFirst().run();
        assertTrue(actions.messages.isEmpty());
    }

    @Test
    void closeLinearizesAfterAnInFlightApplyAndRejectsEveryPostCloseApply() throws Exception {
        CloseLinearizationActions actions = new CloseLinearizationActions();
        BungeeDispositionExecutor executor = executor(
                BungeeDispositionExecutionMode.MONITOR, actions, new ArrayList<>());
        AtomicReference<BungeeDispositionExecutor.Result> applyResult = new AtomicReference<>();
        AtomicBoolean closeReturned = new AtomicBoolean();

        Thread applyThread = new Thread(
                () -> applyResult.set(executor.apply(event(DispositionAction.WARN, "in-flight"))),
                "bungee-disposition-in-flight-apply");
        applyThread.start();
        assertTrue(actions.actionEntered.await(2, TimeUnit.SECONDS));

        Thread closeThread = new Thread(() -> {
            executor.close();
            closeReturned.set(true);
        }, "bungee-disposition-close");
        closeThread.start();
        assertTrue(awaitThreadState(closeThread, Thread.State.BLOCKED, 2, TimeUnit.SECONDS),
                "close must wait on the same monitor as an already-running apply");
        assertFalse(closeReturned.get());

        actions.releaseAction.countDown();
        applyThread.join(2_000);
        closeThread.join(2_000);
        assertFalse(applyThread.isAlive());
        assertFalse(closeThread.isAlive());
        assertEquals(BungeeDispositionExecutor.Status.WARN_SENT, applyResult.get().status());
        assertTrue(closeReturned.get());
        assertEquals(1, actions.actionCalls);

        assertEquals(BungeeDispositionExecutor.Status.ACTION_UNAVAILABLE,
                executor.apply(event(DispositionAction.WARN, "after-close")).status());
        assertEquals(1, actions.actionCalls, "a closed executor must not initiate a platform action");
    }

    @Test
    void boundedIdempotencySetRejectsNewWorkButPreservesDuplicatesAndExactCleanupFreesOneSlot() {
        FakeActions actions = new FakeActions();
        BungeeDispositionExecutor executor = new BungeeDispositionExecutor(
                BungeeDispositionExecutionMode.MONITOR, targets(), 4, ignored -> { }, actions, CLOCK,
                ignored -> true, (ignored, result) -> { }, 2);
        AuthenticatedManifestDispositionEvent first = eventWithAuthorization(
                DispositionAction.WARN, "session-one",
                UUID.fromString("00000000-0000-0000-0000-000000000101"));
        AuthenticatedManifestDispositionEvent second = eventWithAuthorization(
                DispositionAction.WARN, "session-two",
                UUID.fromString("00000000-0000-0000-0000-000000000102"));
        AuthenticatedManifestDispositionEvent third = eventWithAuthorization(
                DispositionAction.WARN, "session-three",
                UUID.fromString("00000000-0000-0000-0000-000000000103"));

        assertEquals(BungeeDispositionExecutor.Status.WARN_SENT,
                executor.apply(first).status());
        assertEquals(BungeeDispositionExecutor.Status.WARN_SENT,
                executor.apply(second).status());
        assertEquals(BungeeDispositionExecutor.Status.DUPLICATE,
                executor.apply(first).status(),
                "an existing key stays a duplicate even when the set is full");
        assertEquals(BungeeDispositionExecutor.Status.ACTION_UNAVAILABLE,
                executor.apply(third).status(), "a new authorization fails closed at capacity");
        assertEquals(2, actions.messages.size(), "capacity rejection must not touch the player");

        executor.clear(PLAYER, "session-one");
        assertEquals(BungeeDispositionExecutor.Status.WARN_SENT,
                executor.apply(third).status(),
                "exact cleanup reclaims the departing session's slot");
        assertEquals(BungeeDispositionExecutor.Status.DUPLICATE,
                executor.apply(second).status(),
                "cleanup must retain every other session's key");
    }

    @Test
    void supersededPolicyIsRecheckedWhenTheQueuedEventExecutes() {
        FakeActions actions = new FakeActions();
        BungeeDispositionExecutor executor = new BungeeDispositionExecutor(
                BungeeDispositionExecutionMode.LIMITED_ROUTE, targets(), 4,
                ignored -> { }, actions, CLOCK, ignored -> false, (ignored, result) -> { });

        assertEquals(BungeeDispositionExecutor.Status.NO_VALID_POLICY,
                executor.apply(event(DispositionAction.DENY)).status());
        assertFalse(actions.denied);
        assertTrue(actions.routeTargets.isEmpty());
        assertTrue(actions.messages.isEmpty());
    }

    @Test
    void staleAuthorizationContextCannotExecuteAHighImpactAction() {
        FakeActions actions = new FakeActions();
        actions.currentAuthorizationContext = false;
        BungeeDispositionExecutor executor = executor(
                BungeeDispositionExecutionMode.LIMITED_ROUTE, actions, new ArrayList<>());

        assertEquals(BungeeDispositionExecutor.Status.STALE_AUTHORIZATION_CONTEXT,
                executor.apply(event(DispositionAction.DENY)).status());
        assertTrue(actions.messages.isEmpty());
        assertTrue(actions.routeTargets.isEmpty());
        assertFalse(actions.denied);
    }

    @Test
    void exactDepartingSessionCleanupCannotEraseReplacementWorkWhenExecutorIsBusy() throws Exception {
        BlockingActions actions = new BlockingActions();
        List<Runnable> scheduled = new java.util.concurrent.CopyOnWriteArrayList<>();
        BungeeDispositionExecutor executor = executor(BungeeDispositionExecutionMode.MONITOR, actions, scheduled);

        // apply() models an audit worker action already running on the scheduler lane. It holds
        // the executor monitor while the physical-login replacement retires its bridge state.
        Thread drainThread = new Thread(() -> executor.apply(event(DispositionAction.WARN, "old-session")),
                "old-session-drain");
        drainThread.start();
        assertTrue(actions.oldActionEntered.await(2, TimeUnit.SECONDS));
        assertTrue(executor.offer(event(DispositionAction.WARN, "replacement-session")),
                "replacement delivery is queued while the old action owns the executor monitor");

        AtomicReference<Throwable> cleanupFailure = new AtomicReference<>();
        Thread cleanup = new Thread(() -> {
            try {
                // The lifecycle lock is deliberately not held here. This call blocks on the
                // executor monitor while an old action is running, then removes old-session only.
                executor.clear(PLAYER, "old-session");
            } catch (Throwable failure) {
                cleanupFailure.set(failure);
            }
        }, "old-session-cleanup");
        cleanup.start();
        actions.releaseOldAction.countDown();
        drainThread.join(2_000);
        cleanup.join(2_000);
        assertFalse(drainThread.isAlive());
        assertFalse(cleanup.isAlive());
        assertEquals(null, cleanupFailure.get());

        assertEquals(1, scheduled.size(), "the preserved replacement event schedules the next bounded drain");
        scheduled.removeFirst().run();
        assertEquals(List.of("replacement-session"), actions.sentSessions,
                "UUID-wide cleanup would incorrectly erase this replacement session");
    }

    @Test
    void delimiterInSessionIdCannotTurnExactCleanupIntoPrefixCleanup() {
        FakeActions actions = new FakeActions();
        BungeeDispositionExecutor executor = executor(BungeeDispositionExecutionMode.MONITOR, actions, new ArrayList<>());
        assertEquals(BungeeDispositionExecutor.Status.WARN_SENT,
                executor.apply(event(DispositionAction.WARN, "a")).status());
        assertEquals(BungeeDispositionExecutor.Status.WARN_SENT,
                executor.apply(event(DispositionAction.WARN, "a|replacement")).status());

        executor.clear(PLAYER, "a");
        assertEquals(BungeeDispositionExecutor.Status.DUPLICATE,
                executor.apply(event(DispositionAction.WARN, "a|replacement")).status(),
                "cleanup for a must not erase an idempotency key for a|replacement");
    }

    @Test
    void independentTrustedAuthorizationsAreNotCollapsedAsDuplicates() {
        FakeActions actions = new FakeActions();
        BungeeDispositionExecutor executor = executor(
                BungeeDispositionExecutionMode.MONITOR, actions, new ArrayList<>());
        AuthenticatedManifestDispositionEvent first = event(DispositionAction.WARN);
        AuthenticatedManifestDispositionEvent second = new AuthenticatedManifestDispositionEvent(
                first.playerId(), first.sessionId(), first.evaluatedAt(), first.highestAction(),
                first.winningRuleId(), first.refreshStatus(), first.activePolicyVersion(),
                first.activePolicySequence(), first.activePolicyExpiresAt(), first.authorityOrigin(),
                Optional.of(UUID.fromString("00000000-0000-0000-0000-000000000100")),
                first.reviewTicket(), Optional.of("44".repeat(32)));

        assertEquals(BungeeDispositionExecutor.Status.WARN_SENT, executor.apply(first).status());
        assertEquals(BungeeDispositionExecutor.Status.WARN_SENT, executor.apply(second).status());
        assertEquals(2, actions.messages.size());
    }

    private static BungeeDispositionExecutor executor(
            BungeeDispositionExecutionMode mode, FakeActions actions, List<Runnable> scheduled) {
        return new BungeeDispositionExecutor(
                mode, targets(), 4, scheduled::add, actions, CLOCK,
                ignored -> true, (ignored, result) -> { });
    }

    private static BungeeDispositionRouteTargets targets() {
        return new BungeeDispositionRouteTargets("limited", "quarantine");
    }

    private static AuthenticatedManifestDispositionEvent event(DispositionAction action) {
        return event(action, "session-a", ProxyPolicyRefreshStatus.ACTIVE);
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
                PLAYER, sessionId, NOW, action,
                status == ProxyPolicyRefreshStatus.ACTIVE ? Optional.of("rule-a") : Optional.empty(),
                status,
                status == ProxyPolicyRefreshStatus.ACTIVE ? Optional.of("policy-a") : Optional.empty(),
                status == ProxyPolicyRefreshStatus.ACTIVE ? Optional.of(2L) : Optional.empty(),
                status == ProxyPolicyRefreshStatus.ACTIVE ? Optional.of(NOW.plusSeconds(60)) : Optional.empty(),
                ObservationOrigin.SERVER_CONFIRMED,
                Optional.of(UUID.fromString("00000000-0000-0000-0000-000000000099")),
                Optional.empty(), Optional.of("33".repeat(32)));
    }

    private static AuthenticatedManifestDispositionEvent eventWithoutWinner() {
        return new AuthenticatedManifestDispositionEvent(
                PLAYER, "session-a", NOW, DispositionAction.WARN, Optional.empty(),
                ProxyPolicyRefreshStatus.ACTIVE, Optional.of("policy-a"), Optional.of(2L),
                Optional.of(NOW.plusSeconds(60)));
    }

    private static AuthenticatedManifestDispositionEvent eventWithAuthorization(
            DispositionAction action, String sessionId, UUID authorizationId) {
        return new AuthenticatedManifestDispositionEvent(
                PLAYER, sessionId, NOW, action, Optional.of("rule-a"),
                ProxyPolicyRefreshStatus.ACTIVE, Optional.of("policy-a"), Optional.of(2L),
                Optional.of(NOW.plusSeconds(60)), ObservationOrigin.SERVER_CONFIRMED,
                Optional.of(authorizationId), Optional.empty(), Optional.of("33".repeat(32)));
    }

    private static boolean awaitThreadState(
            Thread thread, Thread.State state, long timeout, TimeUnit unit) throws InterruptedException {
        long deadline = System.nanoTime() + unit.toNanos(timeout);
        while (System.nanoTime() < deadline) {
            if (thread.getState() == state) {
                return true;
            }
            Thread.sleep(1L);
        }
        return thread.getState() == state;
    }

    private static class FakeActions implements BungeeDispositionExecutor.Actions {
        private boolean current = true;
        private boolean verified = true;
        private boolean currentAuthorizationContext = true;
        private boolean denied;
        private boolean banned;
        private BungeeDispositionExecutor.Actions.RouteOutcome routeOutcome =
                BungeeDispositionExecutor.Actions.RouteOutcome.DISPATCHED;
        private final List<String> messages = new ArrayList<>();
        private final List<String> routeTargets = new ArrayList<>();

        @Override public boolean isCurrentAuthenticatedSession(UUID playerId, String sessionId) { return current; }
        @Override public boolean isVerifiedAdmission(UUID playerId) { return verified; }
        @Override public boolean isCurrentAuthorizationContext(
                AuthenticatedManifestDispositionEvent event) { return currentAuthorizationContext; }
        @Override public boolean sendMessage(UUID playerId, String sessionId, String message) {
            messages.add(sessionId + ":" + message);
            return true;
        }
        @Override public BungeeDispositionExecutor.Actions.RouteOutcome routeToServer(
                AuthenticatedManifestDispositionEvent event, String server) {
            routeTargets.add(server);
            return routeOutcome;
        }
        @Override public boolean deny(UUID playerId, String sessionId, String message) { denied = true; return true; }
    }

    private static final class BlockingActions extends FakeActions {
        private final CountDownLatch oldActionEntered = new CountDownLatch(1);
        private final CountDownLatch releaseOldAction = new CountDownLatch(1);
        private final List<String> sentSessions = new java.util.concurrent.CopyOnWriteArrayList<>();

        @Override public boolean sendMessage(UUID playerId, String sessionId, String message) {
            if ("old-session".equals(sessionId)) {
                oldActionEntered.countDown();
                try {
                    if (!releaseOldAction.await(2, TimeUnit.SECONDS)) {
                        return false;
                    }
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    return false;
                }
                return false; // The real lifecycle gate rejects it after replacement.
            }
            sentSessions.add(sessionId);
            return true;
        }
    }

    private static final class CloseLinearizationActions extends FakeActions {
        private final CountDownLatch actionEntered = new CountDownLatch(1);
        private final CountDownLatch releaseAction = new CountDownLatch(1);
        private volatile int actionCalls;

        @Override public boolean sendMessage(UUID playerId, String sessionId, String message) {
            actionCalls++;
            actionEntered.countDown();
            try {
                return releaseAction.await(2, TimeUnit.SECONDS);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }
}
