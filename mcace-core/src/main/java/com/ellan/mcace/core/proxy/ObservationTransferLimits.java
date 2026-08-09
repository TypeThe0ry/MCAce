package com.ellan.mcace.core.proxy;

import java.time.Duration;
import java.util.Objects;

/** Bounded shared limits for neutral artifact-observation transport. */
public record ObservationTransferLimits(
        int maxEnvelopeBytes,
        int maxChunkBytes,
        long maxTotalBytes,
        int maxChunks,
        int maxObservations,
        int maxCompletedTransfersPerPlayer,
        Duration transferTtl) {
    public static final ObservationTransferLimits DEFAULTS = new ObservationTransferLimits(
            30 * 1024, 24 * 1024, 256L * 1024, 32, 4_096, 64, Duration.ofSeconds(30));

    public ObservationTransferLimits {
        Objects.requireNonNull(transferTtl, "transferTtl");
        if (maxEnvelopeBytes <= 0 || maxChunkBytes <= 0 || maxChunkBytes >= maxEnvelopeBytes
                || maxTotalBytes <= 0 || maxChunks <= 0 || maxObservations <= 0
                || maxCompletedTransfersPerPlayer <= 0 || transferTtl.isZero() || transferTtl.isNegative()) {
            throw new IllegalArgumentException("invalid observation transfer limits");
        }
    }
}
