package com.ellan.mcace.protocol.evidence;

import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.EvidenceRequest;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.transport.BoundedPayloadException;
import com.ellan.mcace.protocol.transport.BoundedPayloadTransferLimits;
import java.security.PublicKey;
import java.time.Clock;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

/** Verifies a server-signed, short-lived, single-use evidence request. */
public final class EvidenceRequestVerifier {
    public record VerifiedRequest(String sessionId, String playerId, EvidenceRequest request) {
        public VerifiedRequest {
            Objects.requireNonNull(sessionId, "sessionId");
            Objects.requireNonNull(playerId, "playerId");
            Objects.requireNonNull(request, "request");
        }
    }

    private final Clock clock;
    private final Map<RequestKey, Long> consumed = new HashMap<>();
    private long lastObservedAtEpochMs;

    public EvidenceRequestVerifier(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.lastObservedAtEpochMs = clock.millis();
    }

    /**
     * Validates raw frame size before parsing, then verifies the server signature and shared
     * replay nonce. The request id is consumed only after all binding and expiry checks pass.
     */
    public synchronized VerifiedRequest accept(
            byte[] encodedFrame,
            EnvelopeCodec codec,
            PublicKey serverKey,
            NonceReplayGuard replayGuard,
            String expectedSessionId,
            String expectedPlayerId) throws EnvelopeException {
        Objects.requireNonNull(encodedFrame, "encodedFrame");
        Objects.requireNonNull(codec, "codec");
        Objects.requireNonNull(serverKey, "serverKey");
        Objects.requireNonNull(replayGuard, "replayGuard");
        requireBinding(expectedSessionId, "expectedSessionId");
        requireBinding(expectedPlayerId, "expectedPlayerId");
        try {
            BoundedPayloadTransferLimits.validateFrameBytes(encodedFrame.length);
        } catch (BoundedPayloadException exception) {
            throw new EnvelopeException("evidence request exceeds raw frame budget", exception);
        }
        SignedEnvelope envelope = codec.parse(encodedFrame);
        // EnvelopeCodec's normal entry point claims the shared nonce after generic envelope
        // validation. Evidence requests have additional semantic/binding checks, so validate
        // those first with an isolated guard and claim the caller's guard only at the end.
        codec.verify(envelope, serverKey,
                new NonceReplayGuard(clock, ProtocolConstants.DEFAULT_REPLAY_WINDOW, 1, 1));
        if (envelope.getHeader().getPacketType() != PacketType.EVIDENCE_REQUEST
                || !expectedSessionId.equals(envelope.getHeader().getSessionId())) {
            throw new EnvelopeException("evidence request packet or session mismatch");
        }
        EvidenceRequest request;
        try {
            request = EvidenceRequest.parseFrom(envelope.getPayload());
            if (!request.getUnknownFields().asMap().isEmpty()) {
                throw new IllegalArgumentException("unknown evidence request fields are not accepted");
            }
            EvidenceTransferLimits.validateRequest(request, observedNow());
        } catch (Exception exception) {
            throw new EnvelopeException("invalid evidence request", exception);
        }
        if (!expectedPlayerId.equals(request.getPlayerId())) {
            throw new EnvelopeException("evidence request player binding mismatch");
        }
        purgeExpired(observedNow());
        RequestKey key = new RequestKey(expectedSessionId, request.getRequestId());
        if (consumed.containsKey(key)) {
            throw new EnvelopeException("evidence request has already been consumed");
        }
        if (!replayGuard.accept(envelope.getHeader().getSessionId(), envelope.getHeader().getNonce().toByteArray())) {
            throw new EnvelopeException("replayed nonce");
        }
        consumed.put(key, request.getExpiresAtEpochMs());
        return new VerifiedRequest(expectedSessionId, expectedPlayerId, request);
    }

    private void purgeExpired(long now) {
        Iterator<Map.Entry<RequestKey, Long>> iterator = consumed.entrySet().iterator();
        while (iterator.hasNext()) {
            if (iterator.next().getValue() <= now) {
                iterator.remove();
            }
        }
    }

    private long observedNow() {
        long now = clock.millis();
        if (now > lastObservedAtEpochMs) {
            lastObservedAtEpochMs = now;
        }
        return lastObservedAtEpochMs;
    }

    private static void requireBinding(String value, String name) throws EnvelopeException {
        if (value == null || value.isBlank()) {
            throw new EnvelopeException(name + " is required");
        }
    }

    private record RequestKey(String sessionId, String requestId) { }
}
