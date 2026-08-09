package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent;
import java.time.Clock;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

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

        /** Sends a fixed message only if this exact authenticated session remains current. */
        boolean sendMessage(UUID playerId, String sessionId, String message);

        RouteOutcome routeToServer(AuthenticatedManifestDispositionEvent event, String server);

        boolean deny(UUID playerId, String sessionId, String message);
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
    private final BiConsumer<AuthenticatedManifestDispositionEvent, Result> resultSink;
    private final Set<AppliedKey> appliedKeys = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean drainScheduled = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();

    BungeeDispositionExecutor(
            BungeeDispositionExecutionMode mode,
            BungeeDispositionRouteTargets routeTargets,
            int capacity,
            Consumer<Runnable> schedulerSubmitter,
            Actions actions,
            Clock clock) {
        this(mode, routeTargets, capacity, schedulerSubmitter, actions, clock, (ignored, result) -> { });
    }

    BungeeDispositionExecutor(
            BungeeDispositionExecutionMode mode,
            BungeeDispositionRouteTargets routeTargets,
            int capacity,
            Consumer<Runnable> schedulerSubmitter,
            Actions actions,
            Clock clock,
            BiConsumer<AuthenticatedManifestDispositionEvent, Result> resultSink) {
        this.mode = Objects.requireNonNull(mode, "mode");
        this.routeTargets = Objects.requireNonNull(routeTargets, "routeTargets");
        if (capacity < 1) {
            throw new IllegalArgumentException("invalid Bungee disposition executor bounds");
        }
        this.queue = new ArrayBlockingQueue<>(capacity);
        this.schedulerSubmitter = Objects.requireNonNull(schedulerSubmitter, "schedulerSubmitter");
        this.actions = Objects.requireNonNull(actions, "actions");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.resultSink = Objects.requireNonNull(resultSink, "resultSink");
    }

    boolean offer(AuthenticatedManifestDispositionEvent event) {
        Objects.requireNonNull(event, "event");
        if (closed.get() || !queue.offer(event)) {
            return false;
        }
        scheduleDrain();
        return true;
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
        if (!event.policyIsActiveAt(clock.instant())) {
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
        if (mode != BungeeDispositionExecutionMode.LIMITED_ROUTE
                && event.highestAction().severity() >= DispositionAction.LIMIT.severity()) {
            return new Result(event.highestAction(), Status.NOT_ENFORCED);
        }
        AppliedKey key = AppliedKey.from(event);
        if (appliedKeys.contains(key)) {
            return new Result(event.highestAction(), Status.DUPLICATE);
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
                completed = actions.deny(event.playerId(), event.sessionId(), DENY_MESSAGE);
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
        trimAppliedKeys();
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
    public void close() {
        if (closed.compareAndSet(false, true)) {
            queue.clear();
            appliedKeys.clear();
        }
    }

    private void scheduleDrain() {
        if (!drainScheduled.compareAndSet(false, true)) {
            return;
        }
        try {
            schedulerSubmitter.accept(this::drain);
        } catch (RuntimeException exception) {
            drainScheduled.set(false);
            queue.clear();
        }
    }

    private void trimAppliedKeys() {
        while (appliedKeys.size() > MAX_APPLIED_KEYS) {
            Iterator<AppliedKey> iterator = appliedKeys.iterator();
            if (!iterator.hasNext()) {
                return;
            }
            appliedKeys.remove(iterator.next());
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
            java.util.Optional<Long> activePolicySequence,
            DispositionAction action) {
        private AppliedKey {
            Objects.requireNonNull(playerId, "playerId");
            Objects.requireNonNull(sessionId, "sessionId");
            Objects.requireNonNull(activePolicySequence, "activePolicySequence");
            Objects.requireNonNull(action, "action");
        }

        static AppliedKey from(AuthenticatedManifestDispositionEvent event) {
            return new AppliedKey(
                    event.playerId(),
                    event.sessionId(),
                    event.activePolicySequence(),
                    event.highestAction());
        }
    }
}
