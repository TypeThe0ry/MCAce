package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.EvaluationContext;
import com.ellan.mcace.core.session.AuthenticatedManifest;
import java.time.Clock;
import java.util.Objects;

/** Evaluates the complete authenticated manifest once, without changing session admission. */
public final class AuthenticatedManifestEvaluator {
    private final AuthenticatedManifestObservationDeriver deriver;
    private final SharedProxyDispositionPolicyRuntime runtime;
    private final Clock clock;

    public AuthenticatedManifestEvaluator(
            AuthenticatedManifestObservationDeriver deriver,
            SharedProxyDispositionPolicyRuntime runtime,
            Clock clock) {
        this.deriver = Objects.requireNonNull(deriver, "deriver");
        this.runtime = Objects.requireNonNull(runtime, "runtime");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public AuthenticatedManifestAuditResult evaluate(
            AuthenticatedManifest manifest, EvaluationContext context) {
        Objects.requireNonNull(manifest, "manifest");
        Objects.requireNonNull(context, "context");
        if (!manifest.playerId().equals(context.playerId())) {
            throw new IllegalArgumentException("manifest player does not match evaluation context");
        }
        AuthenticatedManifestDerivation derivation = deriver.derive(manifest);
        ProxyPolicyBatchEvaluation evaluation = runtime.evaluateCachedBatch(
                context, derivation.observations(), 64);
        return new AuthenticatedManifestAuditResult(
                manifest.playerId(), manifest.sessionId(), clock.instant(), evaluation,
                derivation.consistencyIssues());
    }
}
