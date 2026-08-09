package com.ellan.mcace.core.federation;

import com.ellan.mcace.protocol.generated.FederationGrant;
import java.util.Objects;
import java.util.Optional;

/** Source-side consent response result. The frame is a source-signed FEDERATION_GRANT. */
public record FederationGrantResult(
        FederationRuntimeStatus status,
        Optional<FederationGrant> grant,
        Optional<byte[]> outboundFrame) {
    public FederationGrantResult {
        Objects.requireNonNull(status, "status");
        grant = Objects.requireNonNull(grant, "grant");
        outboundFrame = Objects.requireNonNull(outboundFrame, "outboundFrame").map(byte[]::clone);
        if ((status == FederationRuntimeStatus.GRANT_READY)
                != (grant.isPresent() && outboundFrame.isPresent())) {
            throw new IllegalArgumentException("inconsistent federation grant result");
        }
    }

    @Override
    public Optional<byte[]> outboundFrame() {
        return outboundFrame.map(byte[]::clone);
    }

    public static FederationGrantResult rejected(FederationRuntimeStatus status) {
        return new FederationGrantResult(status, Optional.empty(), Optional.empty());
    }
}
