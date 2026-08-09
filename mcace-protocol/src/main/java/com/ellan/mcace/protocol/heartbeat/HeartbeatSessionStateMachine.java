package com.ellan.mcace.protocol.heartbeat;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.Heartbeat;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.protocol.transport.BoundedPayloadTransferLimits;
import com.ellan.mcace.protocol.transport.BoundedPayloadException;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.PublicKey;
import java.time.Clock;
import java.util.Arrays;
import java.util.Objects;

/** Pure signed-heartbeat validator for one authenticated session; no platform or risk action. */
public final class HeartbeatSessionStateMachine {
    private final String sessionId;
    private final byte[] manifestRoot;
    private final long policySequence;
    private final byte[] policyHash;
    private final byte[] aggregateRoot;
    private final Clock clock;
    /** Authentication-time anchor provides the first-heartbeat grace period. */
    private long lastAcceptedAt;
    /** Highest wall-clock observation; prevents rollback-only recovery. */
    private long lastObservedAt;
    private long lastSequence;

    public HeartbeatSessionStateMachine(String sessionId, byte[] manifestRoot, long policySequence, byte[] policyHash,
            byte[] aggregateRoot, Clock clock) {
        this.sessionId = Objects.requireNonNull(sessionId, "sessionId");
        if (sessionId.isBlank()) {
            throw new IllegalArgumentException("session id required");
        }
        if (policySequence == 0L) {
            throw new IllegalArgumentException("policy sequence required");
        }
        this.manifestRoot = hash(manifestRoot, "manifestRoot");
        this.policySequence = policySequence;
        this.policyHash = hash(policyHash, "policyHash");
        this.aggregateRoot = hash(aggregateRoot, "aggregateRoot");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.lastAcceptedAt = clock.millis();
        this.lastObservedAt = lastAcceptedAt;
    }

    public synchronized void accept(byte[] frame, EnvelopeCodec codec, PublicKey key, NonceReplayGuard guard) throws HeartbeatException, EnvelopeException {
        Objects.requireNonNull(frame, "frame");
        try {
            BoundedPayloadTransferLimits.validateFrameBytes(frame.length);
        } catch (BoundedPayloadException e) {
            throw new HeartbeatException("heartbeat frame exceeds common limit", e);
        }
        SignedEnvelope envelope = codec.parse(frame); codec.verify(envelope, key, guard); acceptVerified(envelope);
    }

    public synchronized void acceptVerified(SignedEnvelope envelope) throws HeartbeatException {
        Objects.requireNonNull(envelope, "envelope");
        try {
            BoundedPayloadTransferLimits.validateFrameBytes(envelope.getSerializedSize());
        } catch (BoundedPayloadException e) {
            throw new HeartbeatException("heartbeat frame exceeds common limit", e);
        }
        if (!envelope.hasHeader() || envelope.getHeader().getPacketType() != PacketType.HEARTBEAT
                || !sessionId.equals(envelope.getHeader().getSessionId())) {
            throw new HeartbeatException("heartbeat envelope binding mismatch");
        }
        try {
            validate(Heartbeat.parseFrom(envelope.getPayload()));
        } catch (InvalidProtocolBufferException e) {
            throw new HeartbeatException("malformed heartbeat", e);
        }
    }

    public synchronized HeartbeatHealth health() {
        long now = clock.millis();
        if (now > lastObservedAt) {
            lastObservedAt = now;
        }
        long age = elapsedMillis(lastObservedAt, lastAcceptedAt);
        if (age > ProtocolConstants.HEARTBEAT_MISSING_AFTER.toMillis()) {
            return HeartbeatHealth.MISSING;
        }
        return age > ProtocolConstants.HEARTBEAT_STALE_AFTER.toMillis()
                ? HeartbeatHealth.STALE : HeartbeatHealth.ACTIVE;
    }

    private void validate(Heartbeat heartbeat) throws HeartbeatException {
        if (heartbeat.getSequence() == 0L || Long.compareUnsigned(heartbeat.getSequence(), lastSequence) <= 0
                || heartbeat.getClientStatus() != TrustLevel.VERIFIED
                || !validCurrentServer(heartbeat.getCurrentServer())
                || !Arrays.equals(manifestRoot, heartbeat.getManifestRootSha256().toByteArray())
                || !Arrays.equals(policyHash, heartbeat.getPolicySha256().toByteArray())
                || heartbeat.getPolicySequence() != policySequence
                || !Arrays.equals(aggregateRoot, heartbeat.getAggregateRootSha256().toByteArray())) {
            throw new HeartbeatException("invalid, replayed, or mismatched heartbeat");
        }
        lastSequence = heartbeat.getSequence();
        long acceptedAt = clock.millis();
        // A valid signed heartbeat is the only event allowed to recover after a
        // wall-clock rollback; invalid input leaves both freshness anchors intact.
        lastAcceptedAt = acceptedAt;
        lastObservedAt = acceptedAt;
    }

    private static long elapsedMillis(long now, long reference) {
        if (now <= reference) {
            return 0L;
        }
        long elapsed = now - reference;
        return elapsed < 0L ? Long.MAX_VALUE : elapsed;
    }

    private static boolean validCurrentServer(String value) {
        return !value.isBlank()
                && value.length() <= ProtocolConstants.MAX_HEARTBEAT_CURRENT_SERVER_CHARS
                && value.chars().noneMatch(Character::isISOControl);
    }

    private static byte[] hash(byte[] value, String name) {
        if (value == null || value.length != 32) {
            throw new IllegalArgumentException(name + " must be SHA-256");
        }
        return value.clone();
    }
}
