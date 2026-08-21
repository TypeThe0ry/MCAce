package com.ellan.mcace.core.admission;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import com.ellan.mcace.sdk.RiskBand;
import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

final class SignedAdmissionSnapshotCodecTest {
    private final UUID playerId = UUID.randomUUID();
    private final MutableClock clock = new MutableClock(Instant.parse("2026-08-08T09:00:00Z"));
    private KeyPair identity;
    private SignedAdmissionSnapshotCodec codec;
    private NonceReplayGuard replayGuard;

    @BeforeEach
    void setUp() throws Exception {
        identity = Ed25519Keys.generate(new SecureRandom());
        codec = new SignedAdmissionSnapshotCodec(clock, new SecureRandom());
        replayGuard = new NonceReplayGuard(clock, ProtocolConstants.DEFAULT_REPLAY_WINDOW);
    }

    @Test
    void roundTripsAndRejectsReplay() throws Exception {
        SignedAdmissionSnapshotCodec.SignedAdmissionSnapshot signed = codec.signWithExpiry(
                snapshot(), Duration.ofSeconds(15), 42, identity.getPrivate());
        byte[] frame = signed.encodedFrame();

        SignedAdmissionSnapshotCodec.VerifiedAdmissionSnapshot verified = codec.verify(
                frame, playerId, identity.getPublic(), replayGuard);

        assertEquals(snapshot(), verified.snapshot());
        assertEquals(clock.instant().plusSeconds(15), signed.expiresAt());
        assertEquals(clock.instant().plusSeconds(15), verified.expiresAt());
        assertEquals(42, verified.transportSequence());
        assertThrows(EnvelopeException.class,
                () -> codec.verify(frame, playerId, identity.getPublic(), replayGuard));
    }

    @Test
    void returnedExpiryExactlyMatchesMillisecondPrecisionWireExpiry() throws Exception {
        clock.advance(Duration.ofNanos(987_654_321L));
        SignedAdmissionSnapshotCodec.SignedAdmissionSnapshot signed = codec.signWithExpiry(
                snapshot(), Duration.ofSeconds(15), 43, identity.getPrivate());

        SignedAdmissionSnapshotCodec.VerifiedAdmissionSnapshot verified = codec.verify(
                signed.encodedFrame(), playerId, identity.getPublic(), replayGuard);
        Instant expected = Instant.ofEpochMilli(clock.instant().plusSeconds(15).toEpochMilli());

        assertEquals(expected, signed.expiresAt());
        assertEquals(expected, verified.expiresAt());
    }

    @Test
    void rejectsWrongCarrierAndForgedSignature() throws Exception {
        byte[] frame = codec.sign(snapshot(), Duration.ofSeconds(15), 1, identity.getPrivate());
        assertThrows(EnvelopeException.class,
                () -> codec.verify(frame, UUID.randomUUID(), identity.getPublic(), replayGuard));

        SignedEnvelope envelope = SignedEnvelope.parseFrom(frame);
        byte[] signature = envelope.getSignature().toByteArray();
        signature[0] ^= 1;
        byte[] forged = envelope.toBuilder().setSignature(ByteString.copyFrom(signature)).build().toByteArray();
        assertThrows(EnvelopeException.class,
                () -> codec.verify(forged, playerId, identity.getPublic(), replayGuard));
    }

    @Test
    void rejectsExpiredTransportSnapshot() throws Exception {
        byte[] frame = codec.sign(snapshot(), Duration.ofSeconds(5), 1, identity.getPrivate());
        clock.advance(Duration.ofSeconds(6));

        assertThrows(EnvelopeException.class,
                () -> codec.verify(frame, playerId, identity.getPublic(), replayGuard));
    }

    @Test
    void refusesToSignInconsistentRiskScore() {
        PlayerSecuritySnapshot inconsistent = new PlayerSecuritySnapshot(
                playerId,
                TrustLevel.VERIFIED,
                AdmissionStatus.VERIFIED,
                1,
                RiskBand.NORMAL,
                "phase2",
                clock.instant(),
                List.of());

        assertThrows(EnvelopeException.class,
                () -> codec.sign(inconsistent, Duration.ofSeconds(15), 1, identity.getPrivate()));
    }

    private PlayerSecuritySnapshot snapshot() {
        return new PlayerSecuritySnapshot(
                playerId,
                TrustLevel.VERIFIED,
                AdmissionStatus.VERIFIED,
                0,
                RiskBand.NORMAL,
                "phase2",
                clock.instant(),
                List.of());
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }

        private void advance(Duration duration) {
            instant = instant.plus(duration);
        }
    }
}
