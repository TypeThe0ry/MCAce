package com.ellan.mcace.velocity;

import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.proxy.AuthenticatedManifestDispositionEvent;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.time.Clock;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;

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

        /** Revalidates the trusted authorization scope against the current physical login. */
        boolean isCurrentAuthorizationContext(AuthenticatedManifestDispositionEvent event);

        boolean sendMessage(UUID playerId, String sessionId, String message);

        RouteOutcome routeToLimited(UUID playerId, String sessionId);

        default RouteOutcome routeToLimited(AuthenticatedManifestDispositionEvent event) {
            return routeToLimited(event.playerId(), event.sessionId());
        }

        RouteOutcome routeToQuarantine(UUID playerId, String sessionId);

        default RouteOutcome routeToQuarantine(AuthenticatedManifestDispositionEvent event) {
            return routeToQuarantine(event.playerId(), event.sessionId());
        }

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
        QUARANTINED_DISPATCHED,
        DEFERRED_ROUTE,
        DENIED,
        NO_VALID_POLICY,
        STALE_SESSION,
        BASELINE_PROTECTED,
        STALE_AUTHORIZATION_CONTEXT,
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
    private final Predicate<AuthenticatedManifestDispositionEvent> currentPolicy;
    private final Set<AppliedKey> appliedKeys = ConcurrentHashMap.newKeySet();

    VelocityDispositionExecutor(
            VelocityAdmissionConfig.Mode mode,
            Actions actions,
            Clock clock,
            Predicate<AuthenticatedManifestDispositionEvent> currentPolicy) {
        this.mode = Objects.requireNonNull(mode, "mode");
        this.actions = Objects.requireNonNull(actions, "actions");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.currentPolicy = Objects.requireNonNull(currentPolicy, "currentPolicy");
    }

    /** Safe for serialized or concurrent Velocity handoffs; no audit worker touches Player state. */
    synchronized Result apply(AuthenticatedManifestDispositionEvent event) {
        Objects.requireNonNull(event, "event");
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
            // A protocol/risk admission result is a stronger server-side fact than an operational
            // artifact allowlist.  A signed ALLOW or other disposition cannot restore it.
            return new Result(event.highestAction(), Status.BASELINE_PROTECTED);
        }
        if (event.highestAction().severity() >= DispositionAction.LIMIT.severity()
                && !actions.isCurrentAuthorizationContext(event)) {
            return new Result(event.highestAction(), Status.STALE_AUTHORIZATION_CONTEXT);
        }
        if (mode != VelocityAdmissionConfig.Mode.LIMITED_ROUTE
                && event.highestAction().severity() >= DispositionAction.LIMIT.severity()) {
            return new Result(event.highestAction(), Status.NOT_ENFORCED);
        }
        AppliedKey key = AppliedKey.from(event);
        if (appliedKeys.contains(key)) {
            return new Result(event.highestAction(), Status.DUPLICATE);
        }
        if (appliedKeys.size() >= MAX_APPLIED_KEYS) {
            // Retaining existing one-shot history is safer than evicting a live session key and
            // making an old trusted authorization executable again.
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
                // Challenge transport is not wired here. This is only a content-free prompt and
                // audit result; it must never claim that a screenshot challenge was initiated.
                completed = actions.sendMessage(event.playerId(), event.sessionId(), CHALLENGE_MESSAGE);
                status = Status.CHALLENGE_AUDITED;
            }
            case LIMIT -> {
                RouteOutcome outcome = actions.routeToLimited(event);
                if (outcome == RouteOutcome.DEFERRED) {
                    return new Result(event.highestAction(), Status.DEFERRED_ROUTE);
                }
                completed = outcome == RouteOutcome.DISPATCHED;
                status = Status.LIMITED_DISPATCHED;
            }
            case QUARANTINE -> {
                RouteOutcome outcome = actions.routeToQuarantine(event);
                if (outcome == RouteOutcome.DEFERRED) {
                    return new Result(event.highestAction(), Status.DEFERRED_ROUTE);
                }
                completed = outcome == RouteOutcome.DISPATCHED;
                status = Status.QUARANTINED_DISPATCHED;
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

    synchronized void clear(UUID playerId) {
        UUID requiredPlayer = Objects.requireNonNull(playerId, "playerId");
        appliedKeys.removeIf(key -> key.playerId().equals(requiredPlayer));
    }

    synchronized void clearSession(UUID playerId, String sessionId) {
        UUID requiredPlayer = Objects.requireNonNull(playerId, "playerId");
        String requiredSession = Objects.requireNonNull(sessionId, "sessionId");
        appliedKeys.removeIf(key -> key.playerId().equals(requiredPlayer)
                && key.sessionId().equals(requiredSession));
    }

    /** Exact idempotency identity; printable delimiters in a session id cannot alias cleanup. */
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
                    event.playerId(), event.sessionId(),
                    event.activePolicyVersion(), event.activePolicySequence(),
                    event.activePolicyExpiresAt(), event.winningRuleId(),
                    event.highestAction(), event.authorizationId());
        }
    }
}
