package com.ellan.mcace.core.evidence;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Bounded, content-free result returned to a proxy adapter. */
public record EvidenceIngressResult(Status status, List<byte[]> outboundFrames, String detail) {
    public enum Status { ACCEPTED, COMPLETE, REJECTED, EXPIRED, REPLAYED, UNSUPPORTED }

    public EvidenceIngressResult {
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(outboundFrames, "outboundFrames");
        detail = Objects.requireNonNullElse(detail, "");
        if (detail.length() > 256) throw new IllegalArgumentException("detail is too long");
        outboundFrames = outboundFrames.stream().map(bytes -> {
            Objects.requireNonNull(bytes, "outbound frame");
            return bytes.clone();
        }).toList();
    }

    @Override public List<byte[]> outboundFrames() {
        return outboundFrames.stream().map(byte[]::clone).toList();
    }

    @Override public boolean equals(Object other) {
        return other instanceof EvidenceIngressResult that && status == that.status
                && detail.equals(that.detail) && Arrays.deepEquals(outboundFrames.toArray(), that.outboundFrames.toArray());
    }

    @Override public int hashCode() {
        return 31 * (31 * status.hashCode() + detail.hashCode()) + Arrays.deepHashCode(outboundFrames.toArray());
    }
}
