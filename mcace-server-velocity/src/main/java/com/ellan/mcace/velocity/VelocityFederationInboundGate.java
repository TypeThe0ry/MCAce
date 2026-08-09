package com.ellan.mcace.velocity;

import com.ellan.mcace.core.federation.FederationFrameClassifier;
import com.ellan.mcace.core.federation.FederationFrameKind;

/** Bounded packet-type routing only; cryptographic acceptance remains in the core runtime. */
final class VelocityFederationInboundGate {
    enum Decision { NOT_FEDERATION, CONSENT_RESPONSE, PRESENTATION, DROP_SERVER_ONLY }

    private VelocityFederationInboundGate() {
    }

    static Decision classify(boolean handshakeChannel, byte[] frame) {
        if (frame == null) return Decision.NOT_FEDERATION;
        FederationFrameKind kind = FederationFrameClassifier.classify(frame);
        if (!handshakeChannel && kind != FederationFrameKind.NOT_FEDERATION
                && kind != FederationFrameKind.MALFORMED) {
            return Decision.DROP_SERVER_ONLY;
        }
        return switch (kind) {
            case CLIENT_CONSENT_RESPONSE -> Decision.CONSENT_RESPONSE;
            case CLIENT_PRESENTATION -> Decision.PRESENTATION;
            case SERVER_ONLY -> Decision.DROP_SERVER_ONLY;
            case NOT_FEDERATION, MALFORMED -> Decision.NOT_FEDERATION;
        };
    }
}
