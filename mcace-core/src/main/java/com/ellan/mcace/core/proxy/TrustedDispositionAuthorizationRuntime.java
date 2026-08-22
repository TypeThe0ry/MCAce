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
                ObservationOrigin.ADMIN_REVIEWED, Optional.of(operatorId), Optional.of(reviewTicket),
                (authorizationId, authoritativeContext) ->
                        TrustedDispositionCommitments.reviewInput(
                                authorizationId, authoritativeContext, observation));
    }

    /**
     * Persists a high-impact action backed by an independently correlated server provider.  The
     * input wrapper is deliberate: a raw client observation cannot be promoted by this API.
     */
    public AuthenticatedManifestDispositionEvent authorizeServerConfirmation(
            UUID playerId,
            String sessionId,
            EvaluationContext context,
            ServerConfirmedDispositionInput input) throws IOException {
        Objects.requireNonNull(input, "input");
        if (!playerId.equals(input.serverObservation().playerId())
                || !sessionId.equals(input.serverObservation().sessionId())) {
            throw new IllegalArgumentException("server confirmation does not match player session");
        }
        return authorize(playerId, sessionId, context, input.correlatedObservation(),
                ObservationOrigin.SERVER_CONFIRMED, Optional.empty(), Optional.empty(),
                (authorizationId, authoritativeContext) ->
                        TrustedDispositionCommitments.serverInput(
                                authorizationId, authoritativeContext, input));
    }

    private AuthenticatedManifestDispositionEvent authorize(
            UUID playerId,
            String sessionId,
            EvaluationContext context,
            ArtifactObservation observation,
            ObservationOrigin origin,
            Optional<String> operatorId,
            Optional<String> reviewTicket,
            CommitmentFactory commitmentFactory) throws IOException {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(observation, "observation");
        Objects.requireNonNull(operatorId, "operatorId");
        Objects.requireNonNull(reviewTicket, "reviewTicket");
        if (!playerId.equals(context.playerId())) {
            throw new IllegalArgumentException("review player does not match evaluation context");
        }
        if (observation.origin() != origin) {
            throw new IllegalArgumentException("authorization evidence origin does not match authority");
        }
        if (origin == ObservationOrigin.ADMIN_REVIEWED
                && (operatorId.isEmpty() || reviewTicket.isEmpty())) {
            throw new IllegalArgumentException("administrator review requires operator and ticket");
        }
        if (origin == ObservationOrigin.SERVER_CONFIRMED
                && (operatorId.isPresent() || reviewTicket.isPresent())) {
            throw new IllegalArgumentException("server confirmation cannot impersonate an operator review");
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
                commitmentFactory.create(authorizationId, authoritativeContext),
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

    @FunctionalInterface
    private interface CommitmentFactory {
        String create(UUID authorizationId, EvaluationContext authoritativeContext);
    }
}
