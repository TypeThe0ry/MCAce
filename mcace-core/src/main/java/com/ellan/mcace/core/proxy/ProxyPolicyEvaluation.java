package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.DispositionDecision;
import java.util.Objects;
import java.util.Optional;
import java.time.Instant;

/** The explainable output returned equally to Velocity and BungeeCord adapters. */
public record ProxyPolicyEvaluation(
        ProxyFamily proxyFamily,
        DispositionDecision decision,
        ProxyPolicyRefreshStatus refreshStatus,
        Optional<String> activePolicyVersion,
        Optional<Long> activePolicySequence,
        Optional<Instant> activePolicyExpiresAt) {
    public ProxyPolicyEvaluation(
            ProxyFamily proxyFamily,
            DispositionDecision decision,
            ProxyPolicyRefreshStatus refreshStatus,
            Optional<String> activePolicyVersion,
            Optional<Long> activePolicySequence) {
        this(proxyFamily, decision, refreshStatus, activePolicyVersion, activePolicySequence, Optional.empty());
    }

    public ProxyPolicyEvaluation {
        Objects.requireNonNull(proxyFamily, "proxyFamily");
        Objects.requireNonNull(decision, "decision");
        Objects.requireNonNull(refreshStatus, "refreshStatus");
        Objects.requireNonNull(activePolicyVersion, "activePolicyVersion");
        Objects.requireNonNull(activePolicySequence, "activePolicySequence");
        Objects.requireNonNull(activePolicyExpiresAt, "activePolicyExpiresAt");
        if (activePolicyVersion.isPresent() != activePolicySequence.isPresent()
                || (activePolicyExpiresAt.isPresent() && activePolicySequence.isEmpty())) {
            throw new IllegalArgumentException("active policy identity must be complete");
        }
    }
}
