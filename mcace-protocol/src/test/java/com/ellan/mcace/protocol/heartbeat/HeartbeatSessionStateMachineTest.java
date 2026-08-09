package com.ellan.mcace.protocol.heartbeat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.EnvelopeHeader;
import com.ellan.mcace.protocol.generated.Heartbeat;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.google.protobuf.ByteString;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZoneId;
import org.junit.jupiter.api.Test;

final class HeartbeatSessionStateMachineTest {
    @Test void rejectsZeroReplayAndRootPolicyMismatchWithoutCheatState() throws Exception {
        byte[] manifest = new byte[32]; byte[] policy = new byte[32]; byte[] aggregate = new byte[32];
        MutableClock clock = new MutableClock(1_800_000_000_000L);
        HeartbeatSessionStateMachine state = new HeartbeatSessionStateMachine("s", manifest, 3, policy, aggregate, clock);
        assertEquals(HeartbeatHealth.ACTIVE, state.health());
        assertThrows(HeartbeatException.class, () -> state.acceptVerified(envelope(heartbeat(0, manifest, policy, aggregate))));
        state.acceptVerified(envelope(heartbeat(1, manifest, policy, aggregate)));
        assertEquals(HeartbeatHealth.ACTIVE, state.health());
        assertThrows(HeartbeatException.class, () -> state.acceptVerified(envelope(heartbeat(1, manifest, policy, aggregate))));
        byte[] wrong = new byte[32]; wrong[0] = 1;
        assertThrows(HeartbeatException.class, () -> state.acceptVerified(envelope(heartbeat(2, wrong, policy, aggregate))));
        assertThrows(HeartbeatException.class, () -> state.acceptVerified(envelope(heartbeat(2, manifest, wrong, aggregate))));
    }

    @Test
    void usesAuthenticationTimeGraceAndSinglePacketLossDoesNotForceMissing() throws Exception {
        byte[] root = new byte[32];
        MutableClock clock = new MutableClock(10_000L);
        HeartbeatSessionStateMachine state = new HeartbeatSessionStateMachine("s", root, 3, root, root, clock);

        clock.advance(ProtocolConstants.HEARTBEAT_STALE_AFTER.toMillis());
        assertEquals(HeartbeatHealth.ACTIVE, state.health());
        clock.advance(1L);
        assertEquals(HeartbeatHealth.STALE, state.health());
        clock.advance(ProtocolConstants.HEARTBEAT_INTERVAL.toMillis() - 1L);
        assertEquals(HeartbeatHealth.STALE, state.health());
        clock.advance(1L);
        assertEquals(HeartbeatHealth.MISSING, state.health());

        // A later, valid sequence recovers the transport state; gaps represent dropped frames.
        assertDoesNotThrow(() -> state.acceptVerified(envelope(heartbeat(3, root, root, root))));
        assertEquals(HeartbeatHealth.ACTIVE, state.health());
    }

    @Test
    void acceptsOnlyVerifiedAndRejectsInvalidCurrentServerWithoutPoisoningRecovery() throws Exception {
        byte[] root = new byte[32];
        HeartbeatSessionStateMachine state = new HeartbeatSessionStateMachine(
                "s", root, 3, root, root, new MutableClock(100L));

        assertThrows(HeartbeatException.class,
                () -> state.acceptVerified(envelope(heartbeat(2, root, root, root, TrustLevel.TRUSTED, "server"))));
        assertThrows(HeartbeatException.class,
                () -> state.acceptVerified(envelope(heartbeat(2, root, root, root, TrustLevel.SECURE, "server"))));
        assertThrows(HeartbeatException.class,
                () -> state.acceptVerified(envelope(heartbeat(2, root, root, root, TrustLevel.VERIFIED, ""))));
        assertThrows(HeartbeatException.class,
                () -> state.acceptVerified(envelope(heartbeat(2, root, root, root, TrustLevel.VERIFIED, "x".repeat(
                        ProtocolConstants.MAX_HEARTBEAT_CURRENT_SERVER_CHARS + 1)))));

        assertDoesNotThrow(() -> state.acceptVerified(envelope(heartbeat(1, root, root, root))));
        assertDoesNotThrow(() -> state.acceptVerified(envelope(heartbeat(2, root, root, root))));
    }

    @Test
    void clockRollbackDoesNotMoveFreshnessAnchorAndElapsedOverflowFailsClosed() throws Exception {
        byte[] root = new byte[32];
        MutableClock clock = new MutableClock(10_000L);
        HeartbeatSessionStateMachine state = new HeartbeatSessionStateMachine("s", root, 3, root, root, clock);
        state.acceptVerified(envelope(heartbeat(1, root, root, root)));

        clock.setMillis(10_000L + ProtocolConstants.HEARTBEAT_MISSING_AFTER.toMillis() + 1L);
        assertEquals(HeartbeatHealth.MISSING, state.health());
        clock.setMillis(10_001L);
        assertEquals(HeartbeatHealth.MISSING, state.health());
        assertDoesNotThrow(() -> state.acceptVerified(envelope(heartbeat(2, root, root, root))));
        assertEquals(HeartbeatHealth.ACTIVE, state.health());

        MutableClock extremeClock = new MutableClock(Long.MIN_VALUE);
        HeartbeatSessionStateMachine extreme = new HeartbeatSessionStateMachine("s", root, 3, root, root, extremeClock);
        extremeClock.setMillis(Long.MAX_VALUE);
        assertEquals(HeartbeatHealth.MISSING, extreme.health());
    }

    @Test
    void comparesUint64SequenceAndPolicyValuesWithoutSignedLongTruncation() throws Exception {
        byte[] root = new byte[32];
        long unsignedPolicySequence = -1L;
        HeartbeatSessionStateMachine state = new HeartbeatSessionStateMachine(
                "s", root, unsignedPolicySequence, root, root, new MutableClock(100L));

        assertDoesNotThrow(() -> state.acceptVerified(envelope(heartbeat(
                Long.MIN_VALUE, root, root, root, TrustLevel.VERIFIED, "server", unsignedPolicySequence))));
        assertThrows(HeartbeatException.class,
                () -> state.acceptVerified(envelope(heartbeat(
                        Long.MIN_VALUE, root, root, root, TrustLevel.VERIFIED, "server", unsignedPolicySequence))));
    }

    @Test
    void rejectsOversizedHeartbeatFrameBeforeParsing() throws Exception {
        byte[] root = new byte[32];
        HeartbeatSessionStateMachine state = new HeartbeatSessionStateMachine(
                "s", root, 3, root, root, Clock.fixed(Instant.EPOCH, ZoneOffset.UTC));
        assertThrows(HeartbeatException.class,
                () -> state.accept(new byte[ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES + 1], null, null, null));
    }

    private static Heartbeat heartbeat(long seq, byte[] m, byte[] p, byte[] a) {
        return heartbeat(seq, m, p, a, TrustLevel.VERIFIED, "server");
    }

    private static Heartbeat heartbeat(long seq, byte[] m, byte[] p, byte[] a, TrustLevel level, String server) {
        return heartbeat(seq, m, p, a, level, server, 3L);
    }

    private static Heartbeat heartbeat(long seq, byte[] m, byte[] p, byte[] a, TrustLevel level, String server,
            long policySequence) {
        return Heartbeat.newBuilder().setSequence(seq).setCurrentServer(server).setClientStatus(level)
                .setManifestRootSha256(ByteString.copyFrom(m)).setPolicySequence(policySequence)
                .setPolicySha256(ByteString.copyFrom(p)).setAggregateRootSha256(ByteString.copyFrom(a)).build();
    }

    private static SignedEnvelope envelope(Heartbeat heartbeat) {
        return SignedEnvelope.newBuilder().setHeader(EnvelopeHeader.newBuilder()
                .setPacketType(PacketType.HEARTBEAT).setSessionId("s"))
                .setPayload(ByteString.copyFrom(heartbeat.toByteArray())).build();
    }

    private static final class MutableClock extends Clock {
        private long millis;

        private MutableClock(long millis) {
            this.millis = millis;
        }

        private void setMillis(long millis) {
            this.millis = millis;
        }

        private void advance(long delta) {
            millis = Math.addExact(millis, delta);
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
            return Instant.EPOCH;
        }

        @Override
        public long millis() {
            return millis;
        }
    }
}
