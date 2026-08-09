package com.ellan.mcace.velocity;

import com.ellan.mcace.core.proxy.FileSignedDispositionPolicySource;
import com.ellan.mcace.core.proxy.ProxyFamily;
import com.ellan.mcace.core.proxy.ProxyPolicyRefreshStatus;
import com.ellan.mcace.core.proxy.SharedProxyDispositionPolicyRuntime;
import com.ellan.mcace.core.proxy.SignedDispositionPolicySource;
import com.ellan.mcace.protocol.policy.PolicyException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/**
 * Velocity lifecycle adapter for the shared detection-policy runtime.
 *
 * <p>This class deliberately exposes policy health only.  It is not an admission controller and
 * cannot route, disconnect, limit, or otherwise change a player's connection.
 */
final class VelocityDispositionPolicyRuntime {
    private static final Duration ALLOWED_CLOCK_SKEW = Duration.ofSeconds(30);

    private final Path policyPath;
    private final SharedProxyDispositionPolicyRuntime runtime;
    private final boolean sourceAvailable;
    private ProxyPolicyRefreshStatus lastStatus = ProxyPolicyRefreshStatus.OBSERVE_NO_VALID_POLICY;

    private VelocityDispositionPolicyRuntime(
            Path policyPath,
            SharedProxyDispositionPolicyRuntime runtime,
            boolean sourceAvailable) {
        this.policyPath = Objects.requireNonNull(policyPath, "policyPath");
        this.runtime = Objects.requireNonNull(runtime, "runtime");
        this.sourceAvailable = sourceAvailable;
    }

    static VelocityDispositionPolicyRuntime create(Path policyPath, Clock clock, KeyPair identity) {
        Objects.requireNonNull(policyPath, "policyPath");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(identity, "identity");
        Path normalizedPath = policyPath.toAbsolutePath().normalize();
        SignedDispositionPolicySource source;
        boolean available = true;
        try {
            source = new FileSignedDispositionPolicySource(normalizedPath, clock, identity);
        } catch (PolicyException exception) {
            // A storage setup failure must never turn a policy-observation feature into an
            // availability or admission failure.  Do not retain or expose the exception text.
            available = false;
            source = () -> {
                throw new PolicyException("disposition policy source is unavailable");
            };
        }
        return new VelocityDispositionPolicyRuntime(
                normalizedPath,
                new SharedProxyDispositionPolicyRuntime(
                        ProxyFamily.VELOCITY, source, identity.getPublic(), clock, ALLOWED_CLOCK_SKEW),
                available);
    }

    synchronized VelocityDispositionPolicyStatus refresh() {
        lastStatus = runtime.refresh();
        return status();
    }

    synchronized VelocityDispositionPolicyStatus status() {
        Optional<Long> sequence = runtime.activeSequence();
        ProxyPolicyRefreshStatus displayedStatus = sequence.isPresent()
                ? lastStatus
                : ProxyPolicyRefreshStatus.OBSERVE_NO_VALID_POLICY;
        return new VelocityDispositionPolicyStatus(policyPath, displayedStatus, sequence, sourceAvailable);
    }

    /** Shared evaluator retained by this lifecycle owner; package-visible to the audit adapter only. */
    SharedProxyDispositionPolicyRuntime coreRuntime() {
        return runtime;
    }
}
