package com.ellan.mcace.velocity;

import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.time.Clock;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe executor for content-free signed disposition events.
 *
 * <p>The evaluator and its bounded queue may run off-thread.  This class is called only from a
 * Velocity handoff; its Actions port is the sole place allowed to resolve or mutate a
 * Player.  The port deliberately exposes no raw manifest, path, hash, or rule content.</p>
 */
final class VelocityDispositionExecutor {
    private static final int MAX_APPLIED_KEYS = 4_096;
    private static final String NOTICE_MESSAGE =
            "MCAce security notice: your client session requires review.";
    private static final String WARN_MESSAGE =
            "MCAce security warning: this session may be restricted.";
    private static final String CHALLENGE_MESSAGE =
            "MCAce security check: additional verification may be required.";
    private static final String DENY_MESSAGE =
            "MCAce denied this connection under the current signed security policy.";

    interface Actions {
        boolean isCurrentAuthenticatedSession(UUID playerId, String sessionId);

        boolean isVerifiedAdmission(UUID playerId);

        boolean sendMessage(UUID playerId, String sessionId, String message);

        RouteOutcome routeToLimited(UUID playerId, String sessionId);

        RouteOutcome routeToQuarantine(UUID playerId, String sessionId);

        boolean deny(UUID playerId, String sessionId, String message);
    }

    enum Status {
        OBSERVE,
        NOTICE_SENT,
        WARN_SENT,
        CHALLENGE_AUDITED,
        LIMITED_DISPATCHED,
        QUARANTINED_DISPATCHED,
        DEFERRED_ROUTE,
        DENIED,
        NO_VALID_POLICY,
        STALE_SESSION,
        BASELINE_PROTECTED,
        NOT_ENFORCED,
        DUPLICATE,
        ACTION_UNAVAILABLE,
        INCOMPLETE_EVENT
    }

    /** A route request is not a route success: Velocity reports that asynchronously. */
    enum RouteOutcome {
        DISPATCHED,
        DEFERRED,
        UNAVAILABLE
    }

    record Result(DispositionAction action, Status status) {
        Result {
            Objects.requireNonNull(action, "action");
            Objects.requireNonNull(status, "status");
        }
    }

    private final VelocityAdmissionConfig.Mode mode;
    private final Actions actions;
    private final Clock clock;
    private final Set<String> appliedKeys = ConcurrentHashMap.newKeySet();

    VelocityDispositionExecutor(VelocityAdmissionConfig.Mode mode, Actions actions) {
        this(mode, actions, Clock.systemUTC());
    }

    VelocityDispositionExecutor(VelocityAdmissionConfig.Mode mode, Actions actions, Clock clock) {
        this.mode = Objects.requireNonNull(mode, "mode");
        this.actions = Objects.requireNonNull(actions, "actions");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** Safe for serialized or concurrent Velocity handoffs; no audit worker touches Player state. */
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
            // A protocol/risk admission result is a stronger server-side fact than an operational
            // artifact allowlist.  A signed ALLOW or other disposition cannot restore it.
            return new Result(event.highestAction(), Status.BASELINE_PROTECTED);
        }
        if (mode != VelocityAdmissionConfig.Mode.LIMITED_ROUTE
                && event.highestAction().severity() >= DispositionAction.LIMIT.severity()) {
            return new Result(event.highestAction(), Status.NOT_ENFORCED);
        }
        String key = event.idempotencyKey();
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
                // Challenge transport is not wired here. This is only a content-free prompt and
                // audit result; it must never claim that a screenshot challenge was initiated.
                completed = actions.sendMessage(event.playerId(), event.sessionId(), CHALLENGE_MESSAGE);
                status = Status.CHALLENGE_AUDITED;
            }
            case LIMIT -> {
                RouteOutcome outcome = actions.routeToLimited(event.playerId(), event.sessionId());
                if (outcome == RouteOutcome.DEFERRED) {
                    return new Result(event.highestAction(), Status.DEFERRED_ROUTE);
                }
                completed = outcome == RouteOutcome.DISPATCHED;
                status = Status.LIMITED_DISPATCHED;
            }
            case QUARANTINE -> {
                RouteOutcome outcome = actions.routeToQuarantine(event.playerId(), event.sessionId());
                if (outcome == RouteOutcome.DEFERRED) {
                    return new Result(event.highestAction(), Status.DEFERRED_ROUTE);
                }
                completed = outcome == RouteOutcome.DISPATCHED;
                status = Status.QUARANTINED_DISPATCHED;
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

    synchronized void clear(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        appliedKeys.removeIf(key -> key.startsWith(playerId + "|"));
    }

    synchronized void clearSession(UUID playerId, String sessionId) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        appliedKeys.removeIf(key -> key.startsWith(playerId + "|" + sessionId + "|"));
    }

    private void trimAppliedKeys() {
        while (appliedKeys.size() > MAX_APPLIED_KEYS) {
            Iterator<String> iterator = appliedKeys.iterator();
            if (!iterator.hasNext()) return;
            appliedKeys.remove(iterator.next());
        }
    }
}
