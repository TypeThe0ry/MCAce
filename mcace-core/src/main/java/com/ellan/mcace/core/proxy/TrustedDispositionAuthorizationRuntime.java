package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.Confidence;
import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.EvaluationContext;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Evaluates trusted observations and persists authorization before exposing an executable event. */
public final class TrustedDispositionAuthorizationRuntime {
    private final SharedProxyDispositionPolicyRuntime policyRuntime;
    private final TrustedDispositionAuthorizationSink auditSink;

    public TrustedDispositionAuthorizationRuntime(
            SharedProxyDispositionPolicyRuntime policyRuntime,
            TrustedDispositionAuthorizationSink auditSink) {
        this.policyRuntime = Objects.requireNonNull(policyRuntime, "policyRuntime");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
    }

    public AuthenticatedManifestDispositionEvent authorizeAdministratorReview(
            UUID playerId,
            String sessionId,
            EvaluationContext context,
            ArtifactObservation observation,
            String operatorId,
            String reviewTicket) throws IOException {
        return authorize(playerId, sessionId, context, observation,
                Optional.of(operatorId), Optional.of(reviewTicket));
    }

    private AuthenticatedManifestDispositionEvent authorize(
            UUID playerId,
            String sessionId,
            EvaluationContext context,
            ArtifactObservation observation,
            Optional<String> operatorId,
            Optional<String> reviewTicket) throws IOException {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(observation, "observation");
        Objects.requireNonNull(operatorId, "operatorId");
        Objects.requireNonNull(reviewTicket, "reviewTicket");
        if (!playerId.equals(context.playerId())) {
            throw new IllegalArgumentException("review player does not match evaluation context");
        }
        ObservationOrigin origin = observation.origin();
        if (origin != ObservationOrigin.ADMIN_REVIEWED) {
            throw new IllegalArgumentException(
                    "only an administrator review may use the current authorization entrypoint");
        }
        if (operatorId.isEmpty() || reviewTicket.isEmpty()) {
            throw new IllegalArgumentException("administrator review requires operator and ticket");
        }
        if (observation.confidence() != Confidence.CONFIRMED) {
            throw new IllegalArgumentException("trusted authorization requires confirmed confidence");
        }
        SharedProxyDispositionPolicyRuntime.AuthoritativeProxyPolicyEvaluation authoritative =
                policyRuntime.evaluateTrusted(context, observation);
        EvaluationContext authoritativeContext = authoritative.context();
        var authorizedAt = authoritativeContext.evaluatedAt();
        ProxyPolicyEvaluation evaluation = authoritative.evaluation();
        var decision = evaluation.decision();
        if (evaluation.refreshStatus() != ProxyPolicyRefreshStatus.ACTIVE
                || evaluation.activePolicyVersion().isEmpty()
                || evaluation.activePolicySequence().isEmpty()
                || evaluation.activePolicyExpiresAt().isEmpty()
                || !authorizedAt.isBefore(evaluation.activePolicyExpiresAt().orElseThrow())
                || decision.winningRuleId().isEmpty()
                || decision.action().severity() < DispositionAction.LIMIT.severity()) {
            throw new IllegalArgumentException(
                    "trusted authorization requires an active high-impact signed-policy decision");
        }
        UUID authorizationId = UUID.randomUUID();
        String executionContextCommitment =
                TrustedDispositionCommitments.executionContext(authorizationId, authoritativeContext);
        TrustedDispositionAuthorizationRecord record = new TrustedDispositionAuthorizationRecord(
                authorizationId, playerId, authorizedAt,
                TrustedDispositionCommitments.session(authorizationId, sessionId),
                TrustedDispositionCommitments.reviewInput(
                        authorizationId, authoritativeContext, observation),
                executionContextCommitment,
                origin, operatorId, reviewTicket,
                decision.action(), decision.winningRuleId(), evaluation.refreshStatus(),
                evaluation.activePolicyVersion(), evaluation.activePolicySequence(),
                evaluation.activePolicyExpiresAt());
        auditSink.append(record);
        return new AuthenticatedManifestDispositionEvent(
                playerId, sessionId, authorizedAt, decision.action(), decision.winningRuleId(),
                evaluation.refreshStatus(), evaluation.activePolicyVersion(),
                evaluation.activePolicySequence(), evaluation.activePolicyExpiresAt(),
                origin, Optional.of(authorizationId), reviewTicket,
                Optional.of(executionContextCommitment));
    }
}
