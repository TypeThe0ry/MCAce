package com.ellan.mcace.core.federation;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.google.protobuf.InvalidProtocolBufferException;
import java.util.Objects;

/**
 * Bounded outer-envelope classifier for proxy source gates.
 *
 * <p>The result selects the isolated runtime path only. Signature, direction, session, peer pin,
 * PoP, and replay verification still happen inside {@link FederationRuntime}.</p>
 */
public final class FederationFrameClassifier {
    private FederationFrameClassifier() { }

    public static FederationFrameKind classify(byte[] encodedFrame) {
        Objects.requireNonNull(encodedFrame, "encodedFrame");
        if (encodedFrame.length == 0
                || encodedFrame.length > ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES) {
            return FederationFrameKind.MALFORMED;
        }
        try {
            SignedEnvelope envelope = SignedEnvelope.parseFrom(encodedFrame);
            if (!envelope.hasHeader()) {
                return FederationFrameKind.MALFORMED;
            }
            PacketType type = envelope.getHeader().getPacketType();
            return switch (type) {
                case FEDERATION_CONSENT_RESPONSE -> FederationFrameKind.CLIENT_CONSENT_RESPONSE;
                case FEDERATION_PRESENTATION -> FederationFrameKind.CLIENT_PRESENTATION;
                case FEDERATION_CONSENT_REQUEST, FEDERATION_GRANT -> FederationFrameKind.SERVER_ONLY;
                default -> FederationFrameKind.NOT_FEDERATION;
            };
        } catch (InvalidProtocolBufferException | RuntimeException exception) {
            return FederationFrameKind.MALFORMED;
        }
    }
}
