package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Content-free durable authorization proving that a trusted review preceded execution. */
public record TrustedDispositionAuthorizationRecord(
        UUID authorizationId,
        UUID playerId,
        Instant authorizedAt,
        String sessionCommitmentSha256,
        String reviewInputCommitmentSha256,
        String executionContextCommitmentSha256,
        ObservationOrigin origin,
        Optional<String> operatorId,
        Optional<String> reviewTicket,
        DispositionAction action,
        Optional<String> winningRuleId,
        ProxyPolicyRefreshStatus policyStatus,
        Optional<String> policyVersion,
        Optional<Long> policySequence,
        Optional<Instant> policyExpiresAt) {
    public TrustedDispositionAuthorizationRecord {
        Objects.requireNonNull(authorizationId, "authorizationId");
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(authorizedAt, "authorizedAt");
        Objects.requireNonNull(sessionCommitmentSha256, "sessionCommitmentSha256");
        Objects.requireNonNull(reviewInputCommitmentSha256, "reviewInputCommitmentSha256");
        Objects.requireNonNull(executionContextCommitmentSha256,
                "executionContextCommitmentSha256");
        Objects.requireNonNull(origin, "origin");
        Objects.requireNonNull(operatorId, "operatorId");
        Objects.requireNonNull(reviewTicket, "reviewTicket");
        Objects.requireNonNull(action, "action");
        Objects.requireNonNull(winningRuleId, "winningRuleId");
        Objects.requireNonNull(policyStatus, "policyStatus");
        Objects.requireNonNull(policyVersion, "policyVersion");
        Objects.requireNonNull(policySequence, "policySequence");
        Objects.requireNonNull(policyExpiresAt, "policyExpiresAt");
        operatorId.ifPresent(value -> validate(value, 128, "operatorId"));
        reviewTicket.ifPresent(value -> validate(value, 128, "reviewTicket"));
        winningRuleId.ifPresent(value -> validate(value, 128, "winningRuleId"));
        policyVersion.ifPresent(value -> validate(value, 128, "policyVersion"));
        validateCommitment(sessionCommitmentSha256, "sessionCommitmentSha256");
        validateCommitment(reviewInputCommitmentSha256, "reviewInputCommitmentSha256");
        validateCommitment(executionContextCommitmentSha256,
                "executionContextCommitmentSha256");
        if (policyVersion.isPresent() != policySequence.isPresent()
                || (policyExpiresAt.isPresent() && policySequence.isEmpty())) {
            throw new IllegalArgumentException("active policy identity must be complete");
        }
        if (origin != ObservationOrigin.SERVER_CONFIRMED && origin != ObservationOrigin.ADMIN_REVIEWED) {
            throw new IllegalArgumentException("authorization origin is not trusted");
        }
        if (origin == ObservationOrigin.ADMIN_REVIEWED
                && (operatorId.isEmpty() || reviewTicket.isEmpty())) {
            throw new IllegalArgumentException("administrator review requires operator and ticket");
        }
        if (origin == ObservationOrigin.SERVER_CONFIRMED
                && (operatorId.isPresent() || reviewTicket.isPresent())) {
            throw new IllegalArgumentException("server-confirmed authorization cannot impersonate an operator review");
        }
        if (policyStatus != ProxyPolicyRefreshStatus.ACTIVE
                || policyVersion.isEmpty() || policySequence.isEmpty() || policyExpiresAt.isEmpty()
                || !authorizedAt.isBefore(policyExpiresAt.orElseThrow())
                || winningRuleId.isEmpty()
                || action.severity() < DispositionAction.LIMIT.severity()) {
            throw new IllegalArgumentException("authorization must bind an active high-impact policy decision");
        }
    }

    private static void validate(String value, int maxChars, String field) {
        if (value.isBlank() || value.length() > maxChars || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(field + " is outside bounds");
        }
    }

    private static void validateCommitment(String value, String field) {
        if (!value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
    }
}
