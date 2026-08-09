package com.ellan.mcace.protocol.crypto;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.EnvelopeHeader;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.zip.CRC32C;

public final class EnvelopeCodec {
    private final Clock clock;
    private final SecureRandom secureRandom;
    private final int maxPayloadBytes;
    private final long allowedClockSkewMillis;

    public EnvelopeCodec(Clock clock, SecureRandom secureRandom, int maxPayloadBytes, Duration allowedClockSkew) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
        if (maxPayloadBytes <= 0) {
            throw new IllegalArgumentException("maxPayloadBytes must be positive");
        }
        this.maxPayloadBytes = maxPayloadBytes;
        Objects.requireNonNull(allowedClockSkew, "allowedClockSkew");
        if (allowedClockSkew.isNegative()) {
            throw new IllegalArgumentException("allowedClockSkew must not be negative");
        }
        this.allowedClockSkewMillis = allowedClockSkew.toMillis();
    }

    public static EnvelopeCodec defaults() {
        return new EnvelopeCodec(
                Clock.systemUTC(),
                new SecureRandom(),
                ProtocolConstants.MAX_PAYLOAD_BYTES,
                ProtocolConstants.DEFAULT_CLOCK_SKEW);
    }

    public SignedEnvelope sign(PacketType packetType, String sessionId, byte[] payload, PrivateKey privateKey)
            throws EnvelopeException {
        Objects.requireNonNull(packetType, "packetType");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(payload, "payload");
        Objects.requireNonNull(privateKey, "privateKey");
        validatePayloadLength(payload.length);

        byte[] nonce = new byte[ProtocolConstants.NONCE_BYTES];
        secureRandom.nextBytes(nonce);
        EnvelopeHeader header = EnvelopeHeader.newBuilder()
                .setProtocolVersion(ProtocolConstants.CURRENT_VERSION)
                .setPacketType(packetType)
                .setSessionId(sessionId)
                .setTimestampEpochMs(clock.millis())
                .setNonce(ByteString.copyFrom(nonce))
                .setPayloadLength(payload.length)
                .setChecksumCrc32C(checksum(payload))
                .build();
        byte[] signature = signBytes(signingBytes(header, payload), privateKey);
        return SignedEnvelope.newBuilder()
                .setHeader(header)
                .setPayload(ByteString.copyFrom(payload))
                .setSignature(ByteString.copyFrom(signature))
                .build();
    }

    public SignedEnvelope parse(byte[] encoded) throws EnvelopeException {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length > maxPayloadBytes + 8192) {
            throw new EnvelopeException("encoded envelope exceeds configured maximum");
        }
        try {
            return SignedEnvelope.parseFrom(encoded);
        } catch (InvalidProtocolBufferException exception) {
            throw new EnvelopeException("malformed protobuf envelope", exception);
        }
    }

    public void verify(SignedEnvelope envelope, PublicKey publicKey, NonceReplayGuard replayGuard)
            throws EnvelopeException {
        Objects.requireNonNull(envelope, "envelope");
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(replayGuard, "replayGuard");
        if (!envelope.hasHeader()) {
            throw new EnvelopeException("missing envelope header");
        }
        if (!envelope.getUnknownFields().asMap().isEmpty()) {
            throw new EnvelopeException("unknown signed envelope fields");
        }
        EnvelopeHeader header = envelope.getHeader();
        if (!header.getUnknownFields().asMap().isEmpty()) {
            throw new EnvelopeException("unknown envelope header fields");
        }
        if (header.getProtocolVersion() != ProtocolConstants.CURRENT_VERSION) {
            throw new EnvelopeException("unsupported protocol version");
        }
        if (header.getPacketType() == PacketType.PACKET_TYPE_UNSPECIFIED
                || header.getPacketType() == PacketType.UNRECOGNIZED) {
            throw new EnvelopeException("unspecified packet type");
        }
        if (header.getSessionId().isBlank()) {
            throw new EnvelopeException("missing session id");
        }
        if (header.getNonce().size() != ProtocolConstants.NONCE_BYTES) {
            throw new EnvelopeException("invalid nonce length");
        }
        byte[] payload = envelope.getPayload().toByteArray();
        validatePayloadLength(payload.length);
        if (header.getPayloadLength() != payload.length) {
            throw new EnvelopeException("payload length mismatch");
        }
        if (header.getChecksumCrc32C() != checksum(payload)) {
            throw new EnvelopeException("payload checksum mismatch");
        }
        long delta = absoluteDeltaMillis(clock.millis(), header.getTimestampEpochMs());
        if (delta > allowedClockSkewMillis) {
            throw new EnvelopeException("timestamp outside allowed clock skew");
        }
        if (!verifyBytes(signingBytes(header, payload), envelope.getSignature().toByteArray(), publicKey)) {
            throw new EnvelopeException("invalid envelope signature");
        }
        if (!replayGuard.accept(header.getSessionId(), header.getNonce().toByteArray())) {
            throw new EnvelopeException("replayed nonce");
        }
    }

    private void validatePayloadLength(int length) throws EnvelopeException {
        if (length > maxPayloadBytes) {
            throw new EnvelopeException("payload exceeds configured maximum");
        }
    }

    private static long absoluteDeltaMillis(long left, long right) {
        if (left >= right) {
            long delta = left - right;
            return delta < 0L ? Long.MAX_VALUE : delta;
        }
        long delta = right - left;
        return delta < 0L ? Long.MAX_VALUE : delta;
    }

    private static int checksum(byte[] payload) {
        CRC32C checksum = new CRC32C();
        checksum.update(payload, 0, payload.length);
        return (int) checksum.getValue();
    }

    private static byte[] signingBytes(EnvelopeHeader header, byte[] payload) {
        byte[] headerBytes = header.toByteArray();
        return ByteBuffer.allocate(Integer.BYTES + headerBytes.length + payload.length)
                .putInt(headerBytes.length)
                .put(headerBytes)
                .put(payload)
                .array();
    }

    private static byte[] signBytes(byte[] content, PrivateKey privateKey) throws EnvelopeException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey);
            signature.update(content);
            return signature.sign();
        } catch (GeneralSecurityException exception) {
            throw new EnvelopeException("failed to sign envelope", exception);
        }
    }

    private static boolean verifyBytes(byte[] content, byte[] signed, PublicKey publicKey) throws EnvelopeException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(publicKey);
            signature.update(content);
            return signature.verify(signed);
        } catch (GeneralSecurityException exception) {
            throw new EnvelopeException("failed to verify envelope", exception);
        }
    }
}
