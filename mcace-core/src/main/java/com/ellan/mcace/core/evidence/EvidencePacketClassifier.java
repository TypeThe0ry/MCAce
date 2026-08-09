package com.ellan.mcace.core.evidence;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.google.protobuf.InvalidProtocolBufferException;

/** Cheap packet-type peek used only after the proxy source gate and raw frame bound. */
public final class EvidencePacketClassifier {
    private EvidencePacketClassifier() { }

    public static boolean isEvidenceFrame(byte[] encodedFrame) {
        if (encodedFrame == null || encodedFrame.length <= 0
                || encodedFrame.length > ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES) {
            return false;
        }
        try {
            PacketType type = SignedEnvelope.parseFrom(encodedFrame).getHeader().getPacketType();
            return type == PacketType.EVIDENCE_REQUEST || type == PacketType.EVIDENCE_RESPONSE
                    || type == PacketType.EVIDENCE_BEGIN || type == PacketType.EVIDENCE_CHUNK
                    || type == PacketType.EVIDENCE_COMMIT || type == PacketType.EVIDENCE_ACK
                    || type == PacketType.EVIDENCE_ERROR;
        } catch (InvalidProtocolBufferException | RuntimeException ignored) {
            return false;
        }
    }

    /** Server-to-client evidence packets must never enter the client receive/risk path. */
    public static boolean isServerOnlyEvidenceFrame(byte[] encodedFrame) {
        if (encodedFrame == null || encodedFrame.length <= 0
                || encodedFrame.length > ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES) return false;
        try {
            PacketType type = SignedEnvelope.parseFrom(encodedFrame).getHeader().getPacketType();
            return type == PacketType.EVIDENCE_REQUEST || type == PacketType.EVIDENCE_ACK
                    || type == PacketType.EVIDENCE_ERROR;
        } catch (InvalidProtocolBufferException | RuntimeException ignored) {
            return false;
        }
    }
}
