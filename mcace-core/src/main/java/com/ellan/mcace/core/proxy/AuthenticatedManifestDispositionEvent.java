package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Content-free, session-bound execution contract for an authenticated disposition evaluation.
 *
 * <p>This is deliberately separate from raw evidence and from platform actions. A proxy adapter
 * may execute only an event produced from an ACTIVE, verified signed policy and must re-check that
 * the session is still current before touching a player. High-impact actions additionally require
 * a durable trusted-source authorization ID; administrator-reviewed actions also require a bounded
 * review ticket.</p>
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
        Optional<Instant> activePolicyExpiresAt,
        ObservationOrigin authorityOrigin,
        Optional<UUID> authorizationId,
        Optional<String> reviewTicket,
        Optional<String> authorizationContextCommitmentSha256) {
    private static final int MAX_SESSION_ID_CHARS = 128;
    private static final int MAX_REVIEW_TICKET_CHARS = 128;

    /** Compatibility constructor for authenticated client-manifest audit events. */
    public AuthenticatedManifestDispositionEvent(
            UUID playerId,
            String sessionId,
            Instant evaluatedAt,
            DispositionAction highestAction,
            Optional<String> winningRuleId,
            ProxyPolicyRefreshStatus refreshStatus,
            Optional<String> activePolicyVersion,
            Optional<Long> activePolicySequence,
            Optional<Instant> activePolicyExpiresAt) {
        this(playerId, sessionId, evaluatedAt, highestAction, winningRuleId, refreshStatus,
                activePolicyVersion, activePolicySequence, activePolicyExpiresAt,
                ObservationOrigin.CLIENT_REPORTED, Optional.empty(), Optional.empty(), Optional.empty());
    }

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
        Objects.requireNonNull(authorityOrigin, "authorityOrigin");
        Objects.requireNonNull(authorizationId, "authorizationId");
        Objects.requireNonNull(reviewTicket, "reviewTicket");
        Objects.requireNonNull(authorizationContextCommitmentSha256,
                "authorizationContextCommitmentSha256");
        if (sessionId.isBlank() || sessionId.length() > MAX_SESSION_ID_CHARS
                || sessionId.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("sessionId is outside the bounded event contract");
        }
        winningRuleId.ifPresent(value -> validateBounded(value, 128, "winningRuleId"));
        reviewTicket.ifPresent(value -> validateBounded(value, MAX_REVIEW_TICKET_CHARS, "reviewTicket"));
        authorizationContextCommitmentSha256.ifPresent(value ->
                validateCommitment(value, "authorizationContextCommitmentSha256"));
        if (activePolicySequence.isPresent() != activePolicyVersion.isPresent()
                || (activePolicyExpiresAt.isPresent() && activePolicySequence.isEmpty())) {
            throw new IllegalArgumentException("active policy identity must be complete");
        }
        boolean trusted = authorityOrigin == ObservationOrigin.SERVER_CONFIRMED
                || authorityOrigin == ObservationOrigin.ADMIN_REVIEWED;
        if (trusted != authorizationId.isPresent()
                || trusted != authorizationContextCommitmentSha256.isPresent()) {
            throw new IllegalArgumentException(
                    "trusted authority must bind one durable authorization id and execution context");
        }
        if (authorityOrigin == ObservationOrigin.ADMIN_REVIEWED && reviewTicket.isEmpty()) {
            throw new IllegalArgumentException("administrator-reviewed authority requires a review ticket");
        }
        if (authorityOrigin != ObservationOrigin.ADMIN_REVIEWED && reviewTicket.isPresent()) {
            throw new IllegalArgumentException("review ticket is valid only for administrator-reviewed authority");
        }
    }

    /** An invalid, expired, or unavailable signed policy can never request execution. */
    public boolean policyIsActive() {
        return refreshStatus == ProxyPolicyRefreshStatus.ACTIVE;
    }

    /** A refresh status alone is not executable evidence; it must name an expiring policy. */
    public boolean hasBoundActivePolicyIdentity() {
        return activePolicyVersion.isPresent()
                && activePolicySequence.isPresent()
                && activePolicyExpiresAt.isPresent();
    }

    public boolean policyIsActiveAt(Instant now) {
        Objects.requireNonNull(now, "now");
        return policyIsActive()
                && hasBoundActivePolicyIdentity()
                && now.isBefore(activePolicyExpiresAt.orElseThrow());
    }

    /** True only for a durably authorized server-confirmed or administrator-reviewed source. */
    public boolean hasTrustedAuthority() {
        return authorizationId.isPresent()
                && authorizationContextCommitmentSha256.isPresent()
                && (authorityOrigin == ObservationOrigin.SERVER_CONFIRMED
                || authorityOrigin == ObservationOrigin.ADMIN_REVIEWED);
    }

    /** Only these actions can change an explicitly enforcement-enabled connection. */
    public boolean hasAdmissionEffect() {
        return policyIsActive()
                && hasBoundActivePolicyIdentity()
                && winningRuleId.isPresent()
                && highestAction.severity() >= DispositionAction.LIMIT.severity()
                && hasTrustedAuthority();
    }

    /** Non-observe actions without retained policy or authority evidence must fail closed. */
    public boolean hasExecutionEvidence() {
        if (highestAction == DispositionAction.OBSERVE || highestAction == DispositionAction.ALLOW) {
            return true;
        }
        if (!policyIsActive() || !hasBoundActivePolicyIdentity() || winningRuleId.isEmpty()) {
            return false;
        }
        return highestAction.severity() < DispositionAction.LIMIT.severity() || hasTrustedAuthority();
    }

    /** Stable key used by adapters to make repeated delivery idempotent per session. */
    public String idempotencyKey() {
        return playerId + "|" + sessionId + "|"
                + activePolicyVersion.orElse("none") + "|"
                + activePolicySequence.map(Object::toString).orElse("none") + "|"
                + activePolicyExpiresAt.map(Instant::toString).orElse("none") + "|"
                + winningRuleId.orElse("none") + "|" + highestAction + "|"
                + authorizationId.map(Object::toString).orElse("advisory") + "|"
                + authorizationContextCommitmentSha256.orElse("no-context");
    }

    private static void validateBounded(String value, int maxChars, String field) {
        if (value.isBlank() || value.length() > maxChars || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(field + " is outside the bounded event contract");
        }
    }

    private static void validateCommitment(String value, String field) {
        if (!value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
    }
}
