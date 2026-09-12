package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent;
import java.time.Clock;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * Bounded handoff from the manifest audit worker to the Bungee scheduler.
 *
 * <p>The worker only calls {@link #offer(AuthenticatedManifestDispositionEvent)}.  Player
 * resolution and every platform action happen in {@link #drain()} after the scheduler handoff.</p>
 */
final class BungeeDispositionExecutor implements AutoCloseable {
    private static final int MAX_APPLIED_KEYS = 4_096;
    private static final int MAX_DRAIN_BATCH = 32;
    private static final String NOTICE_MESSAGE =
            "MCAce security notice: your client session requires review.";
    private static final String WARN_MESSAGE =
            "MCAce security warning: this session may be restricted.";
    private static final String CHALLENGE_MESSAGE =
            "MCAce security check: additional verification may be required.";
    private static final String DENY_MESSAGE =
            "MCAce denied this connection under the current signed security policy.";

    interface Actions {
        enum RouteOutcome {
            /** A Bungee connection request was issued; completion is reported independently by Bungee. */
            DISPATCHED,
            /** The initial backend is not connected yet; exactly one post-connect attempt was retained. */
            DEFERRED,
            /** Player, session, target, or route state is no longer available. */
            UNAVAILABLE
        }

        boolean isCurrentAuthenticatedSession(UUID playerId, String sessionId);

        boolean isVerifiedAdmission(UUID playerId);

        /** Revalidates the trusted authorization scope against the current physical login. */
        boolean isCurrentAuthorizationContext(AuthenticatedManifestDispositionEvent event);

        /** Sends a fixed message only if this exact authenticated session remains current. */
        boolean sendMessage(UUID playerId, String sessionId, String message);

        RouteOutcome routeToServer(AuthenticatedManifestDispositionEvent event, String server);

        boolean deny(UUID playerId, String sessionId, String message);

        default boolean deny(AuthenticatedManifestDispositionEvent event, String message) {
            return deny(event.playerId(), event.sessionId(), message);
        }
    }

    enum Status {
        OBSERVE,
        NOTICE_SENT,
        WARN_SENT,
        CHALLENGE_AUDITED,
        LIMITED_DISPATCHED,
        LIMITED_DEFERRED,
        QUARANTINED_DISPATCHED,
        QUARANTINED_DEFERRED,
        DENIED,
        NO_VALID_POLICY,
        STALE_SESSION,
        BASELINE_PROTECTED,
        STALE_AUTHORIZATION_CONTEXT,
        NOT_ENFORCED,
        DUPLICATE,
        ACTION_UNAVAILABLE,
        INCOMPLETE_EVENT,
        QUEUE_SATURATED
    }

    record Result(DispositionAction action, Status status) {
        Result {
            Objects.requireNonNull(action, "action");
            Objects.requireNonNull(status, "status");
        }
    }

    private final BungeeDispositionExecutionMode mode;
    private final BungeeDispositionRouteTargets routeTargets;
    private final ArrayBlockingQueue<AuthenticatedManifestDispositionEvent> queue;
    private final Consumer<Runnable> schedulerSubmitter;
    private final Actions actions;
    private final Clock clock;
    private final Predicate<AuthenticatedManifestDispositionEvent> currentPolicy;
    private final BiConsumer<AuthenticatedManifestDispositionEvent, Result> resultSink;
    private final int maxAppliedKeys;
    private final Set<AppliedKey> appliedKeys = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean drainScheduled = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();

    BungeeDispositionExecutor(
            BungeeDispositionExecutionMode mode,
            BungeeDispositionRouteTargets routeTargets,
            int capacity,
            Consumer<Runnable> schedulerSubmitter,
            Actions actions,
            Clock clock,
            Predicate<AuthenticatedManifestDispositionEvent> currentPolicy,
            BiConsumer<AuthenticatedManifestDispositionEvent, Result> resultSink) {
        this(mode, routeTargets, capacity, schedulerSubmitter, actions, clock, currentPolicy,
                resultSink, MAX_APPLIED_KEYS);
    }

    /** Test seam for exercising the idempotency bound without thousands of platform actions. */
    BungeeDispositionExecutor(
            BungeeDispositionExecutionMode mode,
            BungeeDispositionRouteTargets routeTargets,
            int capacity,
            Consumer<Runnable> schedulerSubmitter,
            Actions actions,
            Clock clock,
            Predicate<AuthenticatedManifestDispositionEvent> currentPolicy,
            BiConsumer<AuthenticatedManifestDispositionEvent, Result> resultSink,
            int maxAppliedKeys) {
        this.mode = Objects.requireNonNull(mode, "mode");
        this.routeTargets = Objects.requireNonNull(routeTargets, "routeTargets");
        if (capacity < 1 || maxAppliedKeys < 1) {
            throw new IllegalArgumentException("invalid Bungee disposition executor bounds");
        }
        this.queue = new ArrayBlockingQueue<>(capacity);
        this.schedulerSubmitter = Objects.requireNonNull(schedulerSubmitter, "schedulerSubmitter");
        this.actions = Objects.requireNonNull(actions, "actions");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.currentPolicy = Objects.requireNonNull(currentPolicy, "currentPolicy");
        this.resultSink = Objects.requireNonNull(resultSink, "resultSink");
        this.maxAppliedKeys = maxAppliedKeys;
    }

    synchronized boolean offer(AuthenticatedManifestDispositionEvent event) {
        Objects.requireNonNull(event, "event");
        if (closed.get() || !queue.offer(event)) {
            return false;
        }
        return scheduleDrain();
    }

    /** Runs on the Bungee scheduler lane, never on the audit worker. */
    void drain() {
        if (closed.get()) {
            queue.clear();
            drainScheduled.set(false);
            return;
        }
        try {
            for (int count = 0; count < MAX_DRAIN_BATCH; count++) {
                AuthenticatedManifestDispositionEvent event = queue.poll();
                if (event == null) {
                    break;
                }
                Result result = apply(event);
                try {
                    resultSink.accept(event, result);
                } catch (RuntimeException ignored) {
                    // A status sink must never interrupt disposition draining or player actions.
                }
            }
        } finally {
            drainScheduled.set(false);
            if (!closed.get() && !queue.isEmpty()) {
                scheduleDrain();
            }
        }
    }

    synchronized Result apply(AuthenticatedManifestDispositionEvent event) {
        Objects.requireNonNull(event, "event");
        if (closed.get()) {
            return new Result(event.highestAction(), Status.ACTION_UNAVAILABLE);
        }
        if (!event.policyIsActiveAt(clock.instant()) || !currentPolicy.test(event)) {
            return new Result(event.highestAction(), Status.NO_VALID_POLICY);
        }
        if (!event.hasExecutionEvidence()) {
            return new Result(event.highestAction(), Status.INCOMPLETE_EVENT);
        }
        if (!actions.isCurrentAuthenticatedSession(event.playerId(), event.sessionId())) {
            return new Result(event.highestAction(), Status.STALE_SESSION);
        }
        if (event.highestAction() == DispositionAction.OBSERVE
                || event.highestAction() == DispositionAction.ALLOW) {
            return new Result(event.highestAction(), Status.OBSERVE);
        }
        if (!actions.isVerifiedAdmission(event.playerId())) {
            return new Result(event.highestAction(), Status.BASELINE_PROTECTED);
        }
        if (event.highestAction().severity() >= DispositionAction.LIMIT.severity()
                && !actions.isCurrentAuthorizationContext(event)) {
            return new Result(event.highestAction(), Status.STALE_AUTHORIZATION_CONTEXT);
        }
        if (mode != BungeeDispositionExecutionMode.LIMITED_ROUTE
                && event.highestAction().severity() >= DispositionAction.LIMIT.severity()) {
            return new Result(event.highestAction(), Status.NOT_ENFORCED);
        }
        AppliedKey key = AppliedKey.from(event);
        if (appliedKeys.contains(key)) {
            return new Result(event.highestAction(), Status.DUPLICATE);
        }
        if (appliedKeys.size() >= maxAppliedKeys) {
            // Never evict an active session's one-shot key: eviction could make an old trusted
            // authorization executable again. Exact session cleanup is the only reclamation path.
            return new Result(event.highestAction(), Status.ACTION_UNAVAILABLE);
        }
        boolean completed;
        Status status;
        switch (event.highestAction()) {
            case NOTICE -> {
                completed = actions.sendMessage(event.playerId(), event.sessionId(), NOTICE_MESSAGE);
                status = Status.NOTICE_SENT;
            }
            case WARN -> {
                completed = actions.sendMessage(event.playerId(), event.sessionId(), WARN_MESSAGE);
                status = Status.WARN_SENT;
            }
            case CHALLENGE -> {
                completed = actions.sendMessage(event.playerId(), event.sessionId(), CHALLENGE_MESSAGE);
                status = Status.CHALLENGE_AUDITED;
            }
            case LIMIT -> {
                Actions.RouteOutcome outcome = actions.routeToServer(
                        event, routeTargets.limitedServer());
                completed = outcome != Actions.RouteOutcome.UNAVAILABLE;
                status = outcome == Actions.RouteOutcome.DEFERRED
                        ? Status.LIMITED_DEFERRED : Status.LIMITED_DISPATCHED;
            }
            case QUARANTINE -> {
                Actions.RouteOutcome outcome = actions.routeToServer(
                        event, routeTargets.quarantineServer());
                completed = outcome != Actions.RouteOutcome.UNAVAILABLE;
                status = outcome == Actions.RouteOutcome.DEFERRED
                        ? Status.QUARANTINED_DEFERRED : Status.QUARANTINED_DISPATCHED;
            }
            case DENY -> {
                completed = actions.deny(event, DENY_MESSAGE);
                status = Status.DENIED;
            }
            case ALLOW, OBSERVE -> {
                completed = true;
                status = Status.OBSERVE;
            }
            default -> throw new IllegalStateException("unhandled disposition action");
        }
        if (!completed) {
            return new Result(event.highestAction(), Status.ACTION_UNAVAILABLE);
        }
        appliedKeys.add(key);
        return new Result(event.highestAction(), status);
    }

    /**
     * Removes only one departing authenticated session after its physical login is retired.
     *
     * <p>This method is intentionally called after the adapter releases its lifecycle lock.
     * Executor application takes this monitor and may subsequently ask the adapter to acquire
     * that lifecycle lock; reversing that order here would deadlock a same-UUID replacement.</p>
     */
    synchronized void clear(UUID playerId, String sessionId) {
        UUID requiredPlayer = Objects.requireNonNull(playerId, "playerId");
        String requiredSession = Objects.requireNonNull(sessionId, "sessionId");
        queue.removeIf(event -> event.playerId().equals(requiredPlayer)
                && event.sessionId().equals(requiredSession));
        appliedKeys.removeIf(key -> key.playerId().equals(requiredPlayer)
                && key.sessionId().equals(requiredSession));
    }

    @Override
    public synchronized void close() {
        if (closed.compareAndSet(false, true)) {
            queue.clear();
            appliedKeys.clear();
        }
    }

    private boolean scheduleDrain() {
        if (!drainScheduled.compareAndSet(false, true)) {
            return true;
        }
        try {
            schedulerSubmitter.accept(this::drain);
            return true;
        } catch (RuntimeException exception) {
            drainScheduled.set(false);
            queue.clear();
            return false;
        }
    }

    /**
     * Exact idempotency identity for one authenticated disposition delivery.
     *
     * <p>Do not encode this as a delimiter-separated string. Session identifiers are bounded but
     * deliberately not restricted from containing printable delimiters, so prefix matching would
     * let cleanup for one session erase a replacement session such as {@code a|replacement}.</p>
     */
    private record AppliedKey(
            UUID playerId,
            String sessionId,
            java.util.Optional<String> activePolicyVersion,
            java.util.Optional<Long> activePolicySequence,
            java.util.Optional<java.time.Instant> activePolicyExpiresAt,
            java.util.Optional<String> winningRuleId,
            DispositionAction action,
            java.util.Optional<UUID> authorizationId) {
        private AppliedKey {
            Objects.requireNonNull(playerId, "playerId");
            Objects.requireNonNull(sessionId, "sessionId");
            Objects.requireNonNull(activePolicyVersion, "activePolicyVersion");
            Objects.requireNonNull(activePolicySequence, "activePolicySequence");
            Objects.requireNonNull(activePolicyExpiresAt, "activePolicyExpiresAt");
            Objects.requireNonNull(winningRuleId, "winningRuleId");
            Objects.requireNonNull(action, "action");
            Objects.requireNonNull(authorizationId, "authorizationId");
        }

        static AppliedKey from(AuthenticatedManifestDispositionEvent event) {
            return new AppliedKey(
                    event.playerId(),
                    event.sessionId(),
                    event.activePolicyVersion(),
                    event.activePolicySequence(),
                    event.activePolicyExpiresAt(),
                    event.winningRuleId(),
                    event.highestAction(),
                    event.authorizationId());
        }
    }
}
