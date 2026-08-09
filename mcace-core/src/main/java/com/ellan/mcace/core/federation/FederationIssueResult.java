package com.ellan.mcace.core.federation;

import com.ellan.mcace.protocol.generated.FederationConsentRequest;
import java.util.Objects;
import java.util.Optional;

/** Source-side result. The frame is a server-signed FEDERATION_CONSENT_REQUEST. */
public record FederationIssueResult(
        FederationRuntimeStatus status,
        Optional<FederationConsentRequest> request,
        Optional<byte[]> outboundFrame) {
    public FederationIssueResult {
        Objects.requireNonNull(status, "status");
        request = Objects.requireNonNull(request, "request");
        outboundFrame = Objects.requireNonNull(outboundFrame, "outboundFrame")
                .map(byte[]::clone);
        if ((status == FederationRuntimeStatus.CONSENT_ISSUED)
                != (request.isPresent() && outboundFrame.isPresent())) {
            throw new IllegalArgumentException("inconsistent federation issue result");
        }
    }

    @Override
    public Optional<byte[]> outboundFrame() {
        return outboundFrame.map(byte[]::clone);
    }

    public static FederationIssueResult rejected(FederationRuntimeStatus status) {
        return new FederationIssueResult(status, Optional.empty(), Optional.empty());
    }
}
