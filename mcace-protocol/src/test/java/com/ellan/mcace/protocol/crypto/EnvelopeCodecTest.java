package com.ellan.mcace.protocol.crypto;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

final class EnvelopeCodecTest {
    private Clock clock;
    private EnvelopeCodec codec;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        clock = Clock.fixed(Instant.parse("2026-08-08T08:00:00Z"), ZoneOffset.UTC);
        codec = new EnvelopeCodec(clock, new SecureRandom(), 1024, Duration.ofSeconds(30));
        keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    @Test
    void verifiesSignedEnvelopeOnce() throws Exception {
        SignedEnvelope envelope = codec.sign(PacketType.AUTH_REQUEST, "session-1", new byte[] {1, 2, 3}, keyPair.getPrivate());
        NonceReplayGuard guard = new NonceReplayGuard(clock, ProtocolConstants.DEFAULT_REPLAY_WINDOW);

        assertDoesNotThrow(() -> codec.verify(envelope, keyPair.getPublic(), guard));
        assertThrows(EnvelopeException.class, () -> codec.verify(envelope, keyPair.getPublic(), guard));
    }

    @Test
    void rejectsPayloadTampering() throws Exception {
        SignedEnvelope original = codec.sign(PacketType.HEARTBEAT, "session-2", new byte[] {4, 5}, keyPair.getPrivate());
        SignedEnvelope tampered = original.toBuilder().setPayload(ByteString.copyFrom(new byte[] {4, 6})).build();

        assertThrows(
                EnvelopeException.class,
                () -> codec.verify(tampered, keyPair.getPublic(),
                        new NonceReplayGuard(clock, ProtocolConstants.DEFAULT_REPLAY_WINDOW)));
    }

    @Test
    void rejectsTimestampDifferenceWhenAbsoluteDeltaWouldOverflow() throws Exception {
        Clock signingClock = new Clock() {
            @Override public ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(ZoneId zone) { return this; }
            @Override public Instant instant() { return Instant.EPOCH; }
            @Override public long millis() { return Long.MIN_VALUE; }
        };
        EnvelopeCodec signer = new EnvelopeCodec(signingClock, new SecureRandom(), 1024, Duration.ofSeconds(30));
        SignedEnvelope envelope = signer.sign(PacketType.HEARTBEAT, "session-overflow", new byte[] {1}, keyPair.getPrivate());
        EnvelopeCodec verifier = new EnvelopeCodec(
                Clock.fixed(Instant.EPOCH, ZoneOffset.UTC), new SecureRandom(), 1024, Duration.ofSeconds(30));

        assertThrows(EnvelopeException.class,
                () -> verifier.verify(envelope, keyPair.getPublic(),
                        new NonceReplayGuard(Clock.fixed(Instant.EPOCH, ZoneOffset.UTC), ProtocolConstants.DEFAULT_REPLAY_WINDOW)));
    }

    @Test
    void nonceExpirySaturatesInsteadOfOverflowingAtLongMax() {
        Clock nearMaxClock = new Clock() {
            @Override public ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(ZoneId zone) { return this; }
            @Override public Instant instant() { return Instant.EPOCH; }
            @Override public long millis() { return Long.MAX_VALUE - 1L; }
        };
        NonceReplayGuard guard = new NonceReplayGuard(nearMaxClock, Duration.ofSeconds(30));

        assertDoesNotThrow(() -> assertTrue(guard.accept("session", new byte[] {1})));
        assertFalse(guard.accept("session", new byte[] {1}));
    }

    @Test
    void replayGuardFailsClosedAtBoundedCapacity() {
        NonceReplayGuard guard = new NonceReplayGuard(clock, Duration.ofMinutes(5), 6, 2);

        assertTrue(guard.accept("session", new byte[] {1}));
        assertTrue(guard.accept("session", new byte[] {2}));
        assertFalse(guard.accept("session", new byte[] {3}));
        assertFalse(guard.accept("session", new byte[] {1}));
    }

    @Test
    void oneSessionCannotExhaustAnotherSessionsReplayQuota() {
        NonceReplayGuard guard = new NonceReplayGuard(clock, Duration.ofMinutes(5), 100, 2);

        assertTrue(guard.accept("attacker", new byte[] {1}));
        assertTrue(guard.accept("attacker", new byte[] {2}));
        assertFalse(guard.accept("attacker", new byte[] {3}));
        assertTrue(guard.accept("other", new byte[] {1}));
        assertTrue(guard.accept("other", new byte[] {2}));
    }

    @Test
    void thousandSessionsCanMaintainTenHeartbeatsWithinReplayWindow() {
        NonceReplayGuard guard = new NonceReplayGuard(
                clock, ProtocolConstants.DEFAULT_REPLAY_WINDOW,
                ProtocolConstants.MAX_NONCE_REPLAY_ENTRIES,
                ProtocolConstants.MAX_NONCE_REPLAY_ENTRIES_PER_SESSION);

        for (int session = 0; session < 1_000; session++) {
            for (int heartbeat = 0; heartbeat < 10; heartbeat++) {
                assertTrue(guard.accept("session-" + session, new byte[] {(byte) heartbeat}),
                        "replay capacity rejected session " + session + " heartbeat " + heartbeat);
            }
        }
    }
}
