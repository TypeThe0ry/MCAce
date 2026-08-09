package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.DispositionAction;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Content-free, session-bound execution contract for an authenticated manifest evaluation.
 *
 * <p>This is deliberately separate from the raw manifest and from platform actions.  A proxy
 * adapter may execute only an event produced from an ACTIVE, verified signed policy and must
 * re-check that the session is still current before touching a player.</p>
 */
public record AuthenticatedManifestDispositionEvent(
        UUID playerId,
        String sessionId,
        Instant evaluatedAt,
        DispositionAction highestAction,
        Optional<String> winningRuleId,
        ProxyPolicyRefreshStatus refreshStatus,
        Optional<String> activePolicyVersion,
        Optional<Long> activePolicySequence,
        Optional<Instant> activePolicyExpiresAt) {
    private static final int MAX_SESSION_ID_CHARS = 128;

    public AuthenticatedManifestDispositionEvent {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(evaluatedAt, "evaluatedAt");
        Objects.requireNonNull(highestAction, "highestAction");
        Objects.requireNonNull(winningRuleId, "winningRuleId");
        Objects.requireNonNull(refreshStatus, "refreshStatus");
        Objects.requireNonNull(activePolicyVersion, "activePolicyVersion");
        Objects.requireNonNull(activePolicySequence, "activePolicySequence");
        Objects.requireNonNull(activePolicyExpiresAt, "activePolicyExpiresAt");
        if (sessionId.isBlank() || sessionId.length() > MAX_SESSION_ID_CHARS
                || sessionId.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("sessionId is outside the bounded event contract");
        }
        winningRuleId.ifPresent(value -> {
            if (value.isBlank() || value.length() > 128 || value.chars().anyMatch(Character::isISOControl)) {
                throw new IllegalArgumentException("winningRuleId is outside the bounded event contract");
            }
        });
        if (activePolicySequence.isPresent() != activePolicyVersion.isPresent()
                || (activePolicyExpiresAt.isPresent() && activePolicySequence.isEmpty())) {
            throw new IllegalArgumentException("active policy identity must be complete");
        }
    }

    /** An invalid, expired, or unavailable signed policy can never request execution. */
    public boolean policyIsActive() {
        return refreshStatus == ProxyPolicyRefreshStatus.ACTIVE;
    }

    public boolean policyIsActiveAt(Instant now) {
        Objects.requireNonNull(now, "now");
        return policyIsActive()
                && activePolicyExpiresAt.map(now::isBefore).orElse(true);
    }

    /** Only these actions can change an explicitly enforcement-enabled connection. */
    public boolean hasAdmissionEffect() {
        return policyIsActive()
                && winningRuleId.isPresent()
                && (highestAction == DispositionAction.LIMIT
                || highestAction == DispositionAction.QUARANTINE
                || highestAction == DispositionAction.DENY);
    }

    /** Non-observe actions without a retained winning rule are incomplete and must fail closed. */
    public boolean hasExecutionEvidence() {
        return highestAction == DispositionAction.OBSERVE
                || highestAction == DispositionAction.ALLOW
                || winningRuleId.isPresent();
    }

    /** Stable key used by adapters to make repeated delivery idempotent per session. */
    public String idempotencyKey() {
        return playerId + "|" + sessionId + "|"
                + activePolicySequence.map(Object::toString).orElse("none") + "|" + highestAction;
    }
}
