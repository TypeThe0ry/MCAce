package com.ellan.mcace.velocity;

import com.ellan.mcace.core.proxy.ProxyPolicyRefreshStatus;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;

/** Read-only, non-secret diagnostics for Velocity's detection-policy source. */
record VelocityDispositionPolicyStatus(
        Path path,
        ProxyPolicyRefreshStatus refreshStatus,
        Optional<Long> activeSequence,
        boolean sourceAvailable) {
    VelocityDispositionPolicyStatus {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(refreshStatus, "refreshStatus");
        Objects.requireNonNull(activeSequence, "activeSequence");
    }
}
