package com.ellan.mcace.protocol.federation;

import com.ellan.mcace.protocol.generated.PacketType;
import java.util.Objects;

/** Exact four-message federation state-machine directions. */
public final class FederationPacketDirections {
    private FederationPacketDirections() {
    }

    public static void require(
            PacketType packetType, FederationEndpoint sender, FederationEndpoint recipient)
            throws FederationException {
        Objects.requireNonNull(packetType, "packetType");
        Objects.requireNonNull(sender, "sender");
        Objects.requireNonNull(recipient, "recipient");
        boolean allowed = switch (packetType) {
            case FEDERATION_CONSENT_REQUEST -> sender == FederationEndpoint.SOURCE_SERVER
                    && recipient == FederationEndpoint.CLIENT;
            case FEDERATION_CONSENT_RESPONSE -> sender == FederationEndpoint.CLIENT
                    && recipient == FederationEndpoint.SOURCE_SERVER;
            case FEDERATION_GRANT -> sender == FederationEndpoint.SOURCE_SERVER
                    && recipient == FederationEndpoint.CLIENT;
            case FEDERATION_PRESENTATION -> sender == FederationEndpoint.CLIENT
                    && recipient == FederationEndpoint.TARGET_SERVER;
            default -> false;
        };
        if (!allowed) {
            throw new FederationException("packet is not valid for the federation direction");
        }
    }
}
