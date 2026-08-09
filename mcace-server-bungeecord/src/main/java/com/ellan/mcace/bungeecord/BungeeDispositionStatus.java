package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.proxy.ProxyPolicyRefreshStatus;
import java.util.Objects;
import java.util.Optional;

/** Read-only, non-sensitive disposition-policy status for operators. */
record BungeeDispositionStatus(ProxyPolicyRefreshStatus refreshStatus, Optional<Long> activeSequence) {
    BungeeDispositionStatus {
        Objects.requireNonNull(refreshStatus, "refreshStatus");
        Objects.requireNonNull(activeSequence, "activeSequence");
    }

    static BungeeDispositionStatus unavailable() {
        return new BungeeDispositionStatus(ProxyPolicyRefreshStatus.OBSERVE_NO_VALID_POLICY, Optional.empty());
    }
}
