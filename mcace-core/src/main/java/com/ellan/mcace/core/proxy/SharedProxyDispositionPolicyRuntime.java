package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.DispositionDecision;
import com.ellan.mcace.core.disposition.DispositionEngine;
import com.ellan.mcace.core.disposition.DispositionPolicy;
import com.ellan.mcace.core.disposition.DispositionPolicyCompiler;
import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.EvaluationContext;
import com.ellan.mcace.protocol.generated.DispositionPolicyDocument;
import com.ellan.mcace.protocol.generated.SignedDispositionPolicyDocument;
import com.ellan.mcace.protocol.policy.DispositionPolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Shared Velocity/BungeeCord policy boundary.
 *
 * <p>The only platform-specific operation is obtaining a signed document through
 * {@link SignedDispositionPolicySource}.  Signature validation, freshness, strict predecessor
 * chaining, compilation, and the actual decision are common.  This intentionally has no
 * permanent-ban capability.  Fabric integrations pass their artifact observations to
 * {@link #evaluate(EvaluationContext, ArtifactObservation)} after normal protocol authentication.
 */
public final class SharedProxyDispositionPolicyRuntime {
    private final ProxyFamily proxyFamily;
    private final SignedDispositionPolicySource source;
    private final PublicKey trustedKey;
    private final Clock clock;
    private final Duration allowedClockSkew;
    private final DispositionEngine engine;

    private AcceptedPolicy accepted;
    private ProxyPolicyRefreshStatus lastStatus = ProxyPolicyRefreshStatus.OBSERVE_NO_VALID_POLICY;

    public SharedProxyDispositionPolicyRuntime(
            ProxyFamily proxyFamily,
            SignedDispositionPolicySource source,
            PublicKey trustedKey,
            Clock clock,
            Duration allowedClockSkew) {
        this(proxyFamily, source, trustedKey, clock, allowedClockSkew, new DispositionEngine());
    }

    SharedProxyDispositionPolicyRuntime(
            ProxyFamily proxyFamily,
            SignedDispositionPolicySource source,
            PublicKey trustedKey,
            Clock clock,
            Duration allowedClockSkew,
            DispositionEngine engine) {
        this.proxyFamily = Objects.requireNonNull(proxyFamily, "proxyFamily");
        this.source = Objects.requireNonNull(source, "source");
        this.trustedKey = Objects.requireNonNull(trustedKey, "trustedKey");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.allowedClockSkew = Objects.requireNonNull(allowedClockSkew, "allowedClockSkew");
        this.engine = Objects.requireNonNull(engine, "engine");
        if (allowedClockSkew.isNegative()) {
            throw new IllegalArgumentException("allowedClockSkew must not be negative");
        }
    }

    /**
     * Loads a candidate document without allowing an invalid, reordered, or forked chain to
     * replace the current policy. A source failure is treated exactly like an invalid candidate.
     */
    public synchronized ProxyPolicyRefreshStatus refresh() {
        try {
            SignedDispositionPolicyDocument signed = Objects.requireNonNull(
                    source.current(), "signed disposition policy source returned null");
            DispositionPolicyDocument document = DispositionPolicyDocuments.verify(
                    signed, trustedKey, clock, allowedClockSkew);
            byte[] documentHash = DispositionPolicyDocuments.documentSha256(document);
            DispositionPolicy compiled = DispositionPolicyCompiler.compileVerified(document);
            accept(document, documentHash, compiled);
            lastStatus = ProxyPolicyRefreshStatus.ACTIVE;
        } catch (PolicyException | RuntimeException exception) {
            lastStatus = rejectedStatus(exception);
            discardExpiredAcceptedPolicy();
        }
        return lastStatus;
    }

    /**
     * Common evaluation entry point for every proxy and for authenticated Fabric observations.
     * With no valid policy, it produces the explicit default OBSERVE disposition.
     */
    public synchronized ProxyPolicyEvaluation evaluate(
            EvaluationContext context, ArtifactObservation observation) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(observation, "observation");
        ProxyPolicyRefreshStatus status = refresh();
        DispositionDecision decision = accepted == null
                ? observe(observation)
                : engine.evaluate(accepted.policy(), context, observation);
        return new ProxyPolicyEvaluation(
                proxyFamily,
                decision,
                status,
                accepted == null ? Optional.empty() : Optional.of(accepted.document().getVersion()),
                accepted == null ? Optional.empty() : Optional.of(accepted.document().getSequence()),
                accepted == null ? Optional.empty() : Optional.of(java.time.Instant.ofEpochMilli(
                        accepted.document().getExpiresAtEpochMs())));
    }

    /**
     * Evaluates trusted input at this runtime's clock after source refresh completes.
     *
     * <p>The returned context is the exact context used by the engine. A slow policy source or a
     * caller-controlled timestamp therefore cannot produce an authorization outside the exact
     * rule and document validity window.</p>
     */
    synchronized AuthoritativeProxyPolicyEvaluation evaluateTrusted(
            EvaluationContext suppliedContext, ArtifactObservation observation) {
        Objects.requireNonNull(suppliedContext, "suppliedContext");
        Objects.requireNonNull(observation, "observation");
        refresh();
        Instant evaluatedAt = clock.instant();
        EvaluationContext authoritativeContext = new EvaluationContext(
                suppliedContext.playerId(), suppliedContext.proxy(), suppliedContext.backend(),
                suppliedContext.world(), suppliedContext.gameMode(),
                suppliedContext.permissionGroups(), evaluatedAt);
        boolean exactlyActive = accepted != null
                && lastStatus == ProxyPolicyRefreshStatus.ACTIVE
                && !evaluatedAt.isBefore(Instant.ofEpochMilli(
                accepted.document().getEffectiveFromEpochMs()))
                && evaluatedAt.isBefore(Instant.ofEpochMilli(
                accepted.document().getExpiresAtEpochMs()));
        if (!exactlyActive) {
            return new AuthoritativeProxyPolicyEvaluation(
                    authoritativeContext,
                    new ProxyPolicyEvaluation(
                            proxyFamily, observe(observation),
                            ProxyPolicyRefreshStatus.OBSERVE_NO_VALID_POLICY,
                            Optional.empty(), Optional.empty(), Optional.empty()));
        }
        return new AuthoritativeProxyPolicyEvaluation(
                authoritativeContext,
                new ProxyPolicyEvaluation(
                        proxyFamily,
                        engine.evaluate(accepted.policy(), authoritativeContext, observation),
                        lastStatus,
                        Optional.of(accepted.document().getVersion()),
                        Optional.of(accepted.document().getSequence()),
                        Optional.of(Instant.ofEpochMilli(
                                accepted.document().getExpiresAtEpochMs()))));
    }

    /**
     * Evaluates a complete authenticated manifest from the last refreshed policy. It deliberately
     * performs no source I/O: proxies refresh policy on their low-frequency lifecycle task.
     */
    public synchronized ProxyPolicyBatchEvaluation evaluateCachedBatch(
            EvaluationContext context, List<ArtifactObservation> observations, int maxRetainedEvaluations) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(observations, "observations");
        if (maxRetainedEvaluations < 0) throw new IllegalArgumentException("maxRetainedEvaluations must not be negative");
        discardExpiredAcceptedPolicy();
        ProxyPolicyRefreshStatus status = accepted == null ? ProxyPolicyRefreshStatus.OBSERVE_NO_VALID_POLICY : lastStatus;
        java.util.EnumMap<DispositionAction, Integer> counts = new java.util.EnumMap<>(DispositionAction.class);
        int advisoryEnforcementRuleBlocks = 0;
        DispositionAction highestAction = DispositionAction.OBSERVE;
        Optional<String> winningRuleId = Optional.empty();
        boolean evaluatedAny = false;
        List<ProxyPolicyEvaluation> evaluations = new java.util.ArrayList<>(Math.min(observations.size(), maxRetainedEvaluations));
        for (ArtifactObservation observation : observations) {
            Objects.requireNonNull(observation, "observation");
            DispositionDecision decision = accepted == null
                    ? observe(observation)
                    : engine.evaluate(accepted.policy(), context, observation);
            counts.merge(decision.action(), 1, Integer::sum);
            if (!evaluatedAny || decision.action().severity() > highestAction.severity()
                    || (decision.action() == highestAction
                        && winningRuleId.isEmpty() && decision.winningRuleId().isPresent())) {
                highestAction = decision.action();
                winningRuleId = decision.winningRuleId();
            }
            evaluatedAny = true;
            advisoryEnforcementRuleBlocks += (int) decision.explanations().stream()
                    .filter(detail -> "advisory-origin-cannot-enforce".equals(detail.outcome()))
                    .count();
            if (evaluations.size() < maxRetainedEvaluations) evaluations.add(new ProxyPolicyEvaluation(
                    proxyFamily,
                    decision,
                    status,
                    accepted == null ? Optional.empty() : Optional.of(accepted.document().getVersion()),
                    accepted == null ? Optional.empty() : Optional.of(accepted.document().getSequence()),
                    accepted == null ? Optional.empty() : Optional.of(java.time.Instant.ofEpochMilli(
                            accepted.document().getExpiresAtEpochMs()))));
        }
        Optional<String> activePolicyVersion = accepted == null
                ? Optional.empty() : Optional.of(accepted.document().getVersion());
        Optional<Long> activePolicySequence = accepted == null
                ? Optional.empty() : Optional.of(accepted.document().getSequence());
        Optional<Instant> activePolicyExpiresAt = accepted == null
                ? Optional.empty() : Optional.of(Instant.ofEpochMilli(accepted.document().getExpiresAtEpochMs()));
        return new ProxyPolicyBatchEvaluation(status, observations.size(), counts,
                highestAction, winningRuleId, activePolicyVersion, activePolicySequence,
                activePolicyExpiresAt, advisoryEnforcementRuleBlocks, evaluations,
                evaluations.size() < observations.size());
    }

    /** Returns the last known-good policy identity without exposing mutable signing material. */
    public synchronized Optional<Long> activeSequence() {
        discardExpiredAcceptedPolicy();
        return accepted == null ? Optional.empty() : Optional.of(accepted.document().getSequence());
    }

    /**
     * Revalidates an immutable event against the policy that is active at execution time.
     *
     * <p>This closes the authorization-to-action race: an event produced under a policy that was
     * subsequently superseded, expired, or discarded cannot execute from a platform queue.</p>
     */
    public synchronized boolean isCurrentActivePolicy(
            String version,
            long sequence,
            Instant expiresAt,
            String winningRuleId,
            DispositionAction action) {
        return currentActivePolicyMatches(version, sequence, expiresAt, winningRuleId, action);
    }

    /**
     * Starts one platform action under the same policy monitor used by refresh and expiry.
     *
     * <p>The supplier must only initiate the bounded platform operation; it must not wait for an
     * asynchronous route completion. This gives refresh and action initiation one linearization
     * order, rather than leaving a check-then-act policy race.</p>
     */
    public synchronized <T> Optional<T> executeIfCurrentActivePolicy(
            String version,
            long sequence,
            Instant expiresAt,
            String winningRuleId,
            DispositionAction action,
            Supplier<T> operation) {
        Objects.requireNonNull(operation, "operation");
        if (!currentActivePolicyMatches(version, sequence, expiresAt, winningRuleId, action)) {
            return Optional.empty();
        }
        return Optional.of(Objects.requireNonNull(operation.get(), "policy-bound operation result"));
    }

    private boolean currentActivePolicyMatches(
            String version,
            long sequence,
            Instant expiresAt,
            String winningRuleId,
            DispositionAction action) {
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(winningRuleId, "winningRuleId");
        Objects.requireNonNull(action, "action");
        discardExpiredAcceptedPolicy();
        Instant now = clock.instant();
        if (lastStatus != ProxyPolicyRefreshStatus.ACTIVE
                || accepted == null || !now.isBefore(expiresAt)) {
            return false;
        }
        DispositionPolicyDocument document = accepted.document();
        return document.getVersion().equals(version)
                && document.getSequence() == sequence
                && document.getExpiresAtEpochMs() == expiresAt.toEpochMilli()
                && !now.isBefore(Instant.ofEpochMilli(document.getEffectiveFromEpochMs()))
                && now.isBefore(Instant.ofEpochMilli(document.getExpiresAtEpochMs()))
                && accepted.policy().rules().stream()
                        .anyMatch(rule -> rule.ruleId().equals(winningRuleId)
                                && rule.action() == action
                                && rule.activeAt(now));
    }

    private void accept(
            DispositionPolicyDocument candidate, byte[] candidateHash, DispositionPolicy compiled)
            throws PolicyException {
        if (accepted != null) {
            DispositionPolicyDocument current = accepted.document();
            if (!current.getPolicyId().equals(candidate.getPolicyId())) {
                throw new PolicyException("disposition policy id changed without a new runtime");
            }
            int sequenceComparison = Long.compare(candidate.getSequence(), current.getSequence());
            if (sequenceComparison < 0) {
                throw new PolicyException("disposition policy sequence rolled back");
            }
            if (sequenceComparison == 0) {
                if (!MessageDigest.isEqual(candidateHash, accepted.documentHash())) {
                    throw new PolicyException("disposition policy sequence equivocation");
                }
                return;
            }
            if (candidate.getSequence() != current.getSequence() + 1L
                    || !MessageDigest.isEqual(
                    candidate.getPreviousDocumentSha256().toByteArray(), accepted.documentHash())) {
                throw new PolicyException("disposition policy predecessor chain is discontinuous");
            }
        }
        accepted = new AcceptedPolicy(candidate, candidateHash.clone(), compiled);
    }

    private ProxyPolicyRefreshStatus rejectedStatus(Exception exception) {
        String message = exception.getMessage();
        if (message != null && (message.contains("rolled back") || message.contains("predecessor"))) {
            return ProxyPolicyRefreshStatus.REJECTED_ROLLBACK;
        }
        if (message != null && message.contains("equivocation")) {
            return ProxyPolicyRefreshStatus.REJECTED_EQUIVOCATION;
        }
        return accepted == null
                ? ProxyPolicyRefreshStatus.OBSERVE_NO_VALID_POLICY
                : ProxyPolicyRefreshStatus.REJECTED_INVALID;
    }

    private void discardExpiredAcceptedPolicy() {
        if (accepted != null && accepted.document().getExpiresAtEpochMs()
                <= clock.millis() - allowedClockSkew.toMillis()) {
            accepted = null;
        }
    }

    private static DispositionDecision observe(ArtifactObservation observation) {
        return new DispositionDecision(
                observation, DispositionAction.OBSERVE, Optional.empty(), List.of());
    }

    private record AcceptedPolicy(
            DispositionPolicyDocument document, byte[] documentHash, DispositionPolicy policy) {
        private AcceptedPolicy {
            Objects.requireNonNull(document, "document");
            Objects.requireNonNull(documentHash, "documentHash");
            Objects.requireNonNull(policy, "policy");
            if (documentHash.length != 32) {
                throw new IllegalArgumentException("documentHash must be SHA-256");
            }
            documentHash = documentHash.clone();
        }

        @Override
        public byte[] documentHash() {
            return documentHash.clone();
        }
    }

    record AuthoritativeProxyPolicyEvaluation(
            EvaluationContext context, ProxyPolicyEvaluation evaluation) {
        AuthoritativeProxyPolicyEvaluation {
            Objects.requireNonNull(context, "context");
            Objects.requireNonNull(evaluation, "evaluation");
        }
    }
}
