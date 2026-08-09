package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.evidence.EvidencePacketClassifier;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.google.protobuf.InvalidProtocolBufferException;

/**
 * Platform-neutral transport boundary shared by proxy adapters.
 *
 * <p>It deliberately performs only channel/source and bounded packet-type classification. Signature,
 * session, replay, and admission validation remain the responsibility of the shared coordinator.
 * In particular, a client-originated admission update is always consumed and never becomes an
 * authority frame.</p>
 */
public final class ProxyAdapterTransportContract {
    public enum InboundDecision {
        IGNORE,
        CONSUME_ONLY,
        CLIENT_AUTH
    }

    public enum FrameKind {
        UNOWNED,
        ADMISSION,
        PAYLOAD,
        HANDSHAKE,
        HEARTBEAT,
        EVIDENCE_CLIENT,
        EVIDENCE_SERVER_ONLY
    }

    private ProxyAdapterTransportContract() {
    }

    /** Applies the player-only authority gate before an adapter invokes its session bridge. */
    public static InboundDecision decide(String channel, boolean playerSource) {
        FrameKind channelKind = classifyChannel(channel);
        if (channelKind == FrameKind.UNOWNED) {
            return InboundDecision.IGNORE;
        }
        if (!playerSource || channelKind == FrameKind.ADMISSION) {
            return InboundDecision.CONSUME_ONLY;
        }
        return InboundDecision.CLIENT_AUTH;
    }

    /** Classifies an MCAce channel without parsing any untrusted payload. */
    public static FrameKind classifyChannel(String channel) {
        if (ProtocolConstants.HANDSHAKE_CHANNEL.equals(channel)) {
            return FrameKind.HANDSHAKE;
        }
        if (ProtocolConstants.PAYLOAD_CHANNEL.equals(channel)) {
            return FrameKind.PAYLOAD;
        }
        if (ProtocolConstants.ADMISSION_CHANNEL.equals(channel)) {
            return FrameKind.ADMISSION;
        }
        return FrameKind.UNOWNED;
    }

    /**
     * Narrows a client-auth frame for dispatch after {@link #decide(String, boolean)} returns
     * {@link InboundDecision#CLIENT_AUTH}. Malformed frames remain handshake traffic so the
     * coordinator can produce its normal bounded protocol-violation outcome.
     */
    public static FrameKind classifyClientFrame(String channel, byte[] encodedFrame) {
        FrameKind channelKind = classifyChannel(channel);
        if (channelKind != FrameKind.HANDSHAKE) {
            return channelKind;
        }
        if (EvidencePacketClassifier.isServerOnlyEvidenceFrame(encodedFrame)) {
            return FrameKind.EVIDENCE_SERVER_ONLY;
        }
        if (EvidencePacketClassifier.isEvidenceFrame(encodedFrame)) {
            return FrameKind.EVIDENCE_CLIENT;
        }
        try {
            return SignedEnvelope.parseFrom(encodedFrame).getHeader().getPacketType() == PacketType.HEARTBEAT
                    ? FrameKind.HEARTBEAT
                    : FrameKind.HANDSHAKE;
        } catch (InvalidProtocolBufferException | RuntimeException ignored) {
            return FrameKind.HANDSHAKE;
        }
    }
}
