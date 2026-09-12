package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.EvaluationContext;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Runtime boundary for Grim/Vulcan-style provider adapters.
 *
 * <p>Provider adapters hand over only a bounded {@link ServerBehaviorObservation}.  The runtime
 * verifies the provider allow-list, correlates it with a client-reported artifact inside a small
 * time window, evaluates the signed policy, and persists a durable server-confirmed
 * authorization before returning any high-impact execution event.</p>
 */
public final class ServerBehaviorCorrelationRuntime {
    private final ServerBehaviorCorrelator correlator;
    private final SharedProxyDispositionPolicyRuntime policyRuntime;
    private final TrustedDispositionAuthorizationRuntime authorizationRuntime;
    private final Clock clock;
    private final Duration correlationWindow;
    private final Set<String> trustedProviders;

    public ServerBehaviorCorrelationRuntime(
            SharedProxyDispositionPolicyRuntime policyRuntime,
            TrustedDispositionAuthorizationSink auditSink,
            Clock clock,
            Duration correlationWindow,
            Set<String> trustedProviders) {
        this.correlator = new ServerBehaviorCorrelator();
        this.policyRuntime = Objects.requireNonNull(policyRuntime, "policyRuntime");
        this.authorizationRuntime = new TrustedDispositionAuthorizationRuntime(
                policyRuntime, Objects.requireNonNull(auditSink, "auditSink"));
        this.clock = Objects.requireNonNull(clock, "clock");
        this.correlationWindow = Objects.requireNonNull(correlationWindow, "correlationWindow");
        if (correlationWindow.isZero() || correlationWindow.isNegative()) {
            throw new IllegalArgumentException("correlationWindow must be positive");
        }
        Objects.requireNonNull(trustedProviders, "trustedProviders");
        if (trustedProviders.isEmpty()) throw new IllegalArgumentException("trustedProviders is empty");
        this.trustedProviders = Set.copyOf(trustedProviders);
        if (this.trustedProviders.stream().anyMatch(value -> value == null || value.isBlank())) {
            throw new IllegalArgumentException("trustedProviders contains an invalid provider");
        }
    }

    /**
     * Correlates and evaluates a provider signal.  Low-impact decisions are returned for audit;
     * only LIMIT/QUARANTINE/DENY receive a durable executable event.
     */
    public Optional<ServerBehaviorCorrelationResult> correlate(
            UUID playerId,
            String sessionId,
            EvaluationContext context,
            Instant clientObservedAt,
            ArtifactObservation clientObservation,
            ServerBehaviorObservation serverObservation) throws IOException {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(serverObservation, "serverObservation");
        if (!playerId.equals(context.playerId())) {
            throw new IllegalArgumentException("correlation player does not match evaluation context");
        }
        if (!trustedProviders.contains(serverObservation.provider())) return Optional.empty();
        Instant evaluatedAt = clock.instant();
        Optional<ArtifactObservation> correlated = correlator.correlate(
                playerId, sessionId, clientObservedAt, clientObservation,
                serverObservation, correlationWindow, evaluatedAt);
        if (correlated.isEmpty()) return Optional.empty();

        ArtifactObservation evidence = correlated.orElseThrow();
        ProxyPolicyEvaluation evaluation = policyRuntime.evaluate(context, evidence);
        if (evaluation.decision().action().severity() < DispositionAction.LIMIT.severity()) {
            return Optional.of(new ServerBehaviorCorrelationResult(evidence, evaluation, Optional.empty()));
        }
        AuthenticatedManifestDispositionEvent event = authorizationRuntime.authorizeServerConfirmation(
                playerId, sessionId, context,
                new ServerConfirmedDispositionInput(serverObservation, evidence));
        return Optional.of(new ServerBehaviorCorrelationResult(evidence, evaluation, Optional.of(event)));
    }
}
