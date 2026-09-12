package com.ellan.mcace.core.authority;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/** Atomic content-free recovery state for one exact authority lifecycle. */
record ServerAuthorityIssuanceRecovery(
        long lastSequence,
        Optional<Instant> lastObservedAt,
        Optional<Instant> lastIssuedAt) {
    ServerAuthorityIssuanceRecovery {
        if (lastSequence < 0L) {
            throw new IllegalArgumentException("lastSequence cannot be negative");
        }
        lastObservedAt = Objects.requireNonNull(lastObservedAt, "lastObservedAt");
        lastIssuedAt = Objects.requireNonNull(lastIssuedAt, "lastIssuedAt");
        if (lastObservedAt.isPresent() != lastIssuedAt.isPresent()) {
            throw new IllegalArgumentException("authority recovery timestamps must be paired");
        }
        if (lastSequence == 0L && lastObservedAt.isPresent()) {
            throw new IllegalArgumentException("empty authority recovery cannot contain timestamps");
        }
        if (lastObservedAt.isPresent()
                && lastIssuedAt.orElseThrow().isBefore(lastObservedAt.orElseThrow())) {
            throw new IllegalArgumentException("authority recovery issuance predates observation");
        }
    }

    static ServerAuthorityIssuanceRecovery empty() {
        return new ServerAuthorityIssuanceRecovery(0L, Optional.empty(), Optional.empty());
    }
}
