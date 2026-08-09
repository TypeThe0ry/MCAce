package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.admission.SignedAdmissionSnapshotCodec;
import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import com.ellan.mcace.sdk.RiskBand;
import com.ellan.mcace.sdk.RiskReason;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.concurrent.atomic.AtomicInteger;
import java.lang.reflect.Proxy;
import org.bukkit.World;
import org.bukkit.entity.Player;
import org.junit.jupiter.api.Test;

final class PaperAdmissionReceiverTest {
    @Test
    void acceptsFreshProxyStateRejectsRollbackAndExpiresLocally() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-08T09:00:00Z"));
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        InMemoryMCAceApi api = new InMemoryMCAceApi();
        Logger logger = Logger.getAnonymousLogger();
        logger.setLevel(Level.OFF);
        PaperAdmissionReceiver receiver = new PaperAdmissionReceiver(api, identity.getPublic(), clock, logger);
        SignedAdmissionSnapshotCodec signer = new SignedAdmissionSnapshotCodec(clock, new SecureRandom());
        UUID playerId = UUID.randomUUID();

        PlayerSecuritySnapshot verified = snapshot(playerId, clock.instant(), true);
        byte[] verifiedFrame = signer.sign(verified, Duration.ofSeconds(15), 2, identity.getPrivate());
        assertTrue(receiver.receive(playerId, verifiedFrame));
        assertEquals(AdmissionStatus.VERIFIED, api.snapshot(playerId).orElseThrow().admissionStatus());

        clock.advance(Duration.ofSeconds(1));
        PlayerSecuritySnapshot limited = snapshot(playerId, clock.instant(), false);
        byte[] limitedFrame = signer.sign(limited, Duration.ofSeconds(15), 3, identity.getPrivate());
        assertTrue(receiver.receive(playerId, limitedFrame));
        assertEquals(AdmissionStatus.LIMITED, api.snapshot(playerId).orElseThrow().admissionStatus());

        byte[] rollbackFrame = signer.sign(verified, Duration.ofSeconds(15), 2, identity.getPrivate());
        assertFalse(receiver.receive(playerId, rollbackFrame));
        assertEquals(AdmissionStatus.LIMITED, api.snapshot(playerId).orElseThrow().admissionStatus());

        clock.advance(Duration.ofSeconds(16));
        receiver.expire();
        assertTrue(api.snapshot(playerId).isEmpty());
    }

    @Test
    void rejectsSnapshotCarriedByDifferentPlayerWithoutChangingState() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-08-08T09:00:00Z"), ZoneOffset.UTC);
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        InMemoryMCAceApi api = new InMemoryMCAceApi();
        Logger logger = Logger.getAnonymousLogger();
        logger.setLevel(Level.OFF);
        PaperAdmissionReceiver receiver = new PaperAdmissionReceiver(api, identity.getPublic(), clock, logger);
        SignedAdmissionSnapshotCodec signer = new SignedAdmissionSnapshotCodec(clock, new SecureRandom());
        UUID playerId = UUID.randomUUID();
        byte[] frame = signer.sign(
                snapshot(playerId, clock.instant(), true),
                Duration.ofSeconds(15),
                1,
                identity.getPrivate());

        assertFalse(receiver.receive(UUID.randomUUID(), frame));
        assertTrue(api.snapshot(playerId).isEmpty());
    }

    @Test
    void rejectsForgedReplayedExpiredAndWrongCarrierFramesWithoutChangingAcceptedState() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-08T09:00:00Z"));
        KeyPair pinnedProxy = Ed25519Keys.generate(new SecureRandom());
        KeyPair unpinnedSigner = Ed25519Keys.generate(new SecureRandom());
        InMemoryMCAceApi api = new InMemoryMCAceApi();
        Logger logger = Logger.getAnonymousLogger();
        logger.setLevel(Level.OFF);
        PaperAdmissionReceiver receiver = new PaperAdmissionReceiver(api, pinnedProxy.getPublic(), clock, logger);
        SignedAdmissionSnapshotCodec pinnedSigner = new SignedAdmissionSnapshotCodec(clock, new SecureRandom());
        SignedAdmissionSnapshotCodec forgedSigner = new SignedAdmissionSnapshotCodec(clock, new SecureRandom());
        UUID playerId = UUID.randomUUID();

        byte[] limited = pinnedSigner.sign(snapshot(playerId, clock.instant(), false),
                Duration.ofSeconds(15), 1, pinnedProxy.getPrivate());
        assertTrue(receiver.receive(playerId, limited));
        assertStatus(api, playerId, AdmissionStatus.LIMITED);

        byte[] forgedVerified = forgedSigner.sign(snapshot(playerId, clock.instant(), true),
                Duration.ofSeconds(15), 2, unpinnedSigner.getPrivate());
        assertFalse(receiver.receive(playerId, forgedVerified));
        assertStatus(api, playerId, AdmissionStatus.LIMITED);

        byte[] expired = pinnedSigner.sign(snapshot(playerId, clock.instant(), false),
                Duration.ofSeconds(1), 3, pinnedProxy.getPrivate());
        clock.advance(Duration.ofSeconds(2));
        byte[] verified = pinnedSigner.sign(snapshot(playerId, clock.instant(), true),
                Duration.ofSeconds(15), 2, pinnedProxy.getPrivate());
        assertTrue(receiver.receive(playerId, verified));
        assertStatus(api, playerId, AdmissionStatus.VERIFIED);
        assertFalse(receiver.receive(playerId, verified));
        assertStatus(api, playerId, AdmissionStatus.VERIFIED);
        assertFalse(receiver.receive(UUID.randomUUID(), verified));
        assertStatus(api, playerId, AdmissionStatus.VERIFIED);

        assertFalse(receiver.receive(playerId, expired));
        assertStatus(api, playerId, AdmissionStatus.VERIFIED);
    }

    @Test
    void entityScheduledObserverRunsOnlyAfterSignatureAndCarrierVerification() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-08-08T09:00:00Z"), ZoneOffset.UTC);
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        InMemoryMCAceApi api = new InMemoryMCAceApi();
        UUID playerId = UUID.randomUUID();
        AtomicInteger accepted = new AtomicInteger();
        MCAceRuntimeScheduler scheduler = immediateScheduler();
        PaperAdmissionReceiver receiver = new PaperAdmissionReceiver(
                api, identity.getPublic(), clock, Logger.getAnonymousLogger(), scheduler,
                new PaperAdmissionReceiver.AdmissionObserver() {
                    @Override public void accept(Player carrier, PaperAdmissionReceiver.AcceptedAdmission update) {
                        accepted.incrementAndGet();
                    }
                    @Override public void remove(UUID ignored) { }
                });
        SignedAdmissionSnapshotCodec signer = new SignedAdmissionSnapshotCodec(clock, new SecureRandom());
        byte[] frame = signer.sign(snapshot(playerId, clock.instant(), false),
                Duration.ofSeconds(15), 1, identity.getPrivate());
        Player player = player(playerId);

        receiver.onPluginMessageReceived(ProtocolConstants.ADMISSION_CHANNEL, player, frame);
        assertEquals(1, accepted.get());

        byte[] tampered = frame.clone();
        tampered[tampered.length - 1] ^= 1;
        receiver.onPluginMessageReceived(ProtocolConstants.ADMISSION_CHANNEL, player, tampered);
        assertEquals(1, accepted.get());
        assertEquals(AdmissionStatus.LIMITED, api.snapshot(playerId).orElseThrow().admissionStatus());
    }

    @Test
    void wrongChannelAndOversizedInputAreNotScheduledOrPublished() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-08-08T09:00:00Z"), ZoneOffset.UTC);
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        InMemoryMCAceApi api = new InMemoryMCAceApi();
        UUID playerId = UUID.randomUUID();
        AtomicInteger scheduled = new AtomicInteger();
        PaperAdmissionReceiver receiver = new PaperAdmissionReceiver(
                api, identity.getPublic(), clock, Logger.getAnonymousLogger(), countingScheduler(scheduled));
        SignedAdmissionSnapshotCodec signer = new SignedAdmissionSnapshotCodec(clock, new SecureRandom());
        byte[] valid = signer.sign(snapshot(playerId, clock.instant(), true),
                Duration.ofSeconds(15), 1, identity.getPrivate());
        Player player = player(playerId);

        receiver.onPluginMessageReceived("mcace:not-admission", player, valid);
        receiver.onPluginMessageReceived(ProtocolConstants.ADMISSION_CHANNEL, player,
                new byte[ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES + 1]);

        assertEquals(0, scheduled.get());
        assertTrue(api.snapshot(playerId).isEmpty());
    }

    private static void assertStatus(InMemoryMCAceApi api, UUID playerId, AdmissionStatus expected) {
        assertEquals(expected, api.snapshot(playerId).orElseThrow().admissionStatus());
    }

    private static PlayerSecuritySnapshot snapshot(UUID playerId, Instant evaluatedAt, boolean verified) {
        if (verified) {
            return new PlayerSecuritySnapshot(
                    playerId,
                    TrustLevel.VERIFIED,
                    AdmissionStatus.VERIFIED,
                    0,
                    RiskBand.NORMAL,
                    "phase2",
                    evaluatedAt,
                    List.of());
        }
        RiskReason reason = new RiskReason("MISSING_MCACE", 20, "velocity-timeout", evaluatedAt, true);
        return new PlayerSecuritySnapshot(
                playerId,
                TrustLevel.UNKNOWN,
                AdmissionStatus.LIMITED,
                20,
                RiskBand.WATCH,
                "phase2",
                evaluatedAt,
                List.of(reason));
    }

    private static Player player(UUID playerId) {
        return (Player) Proxy.newProxyInstance(PaperAdmissionReceiverTest.class.getClassLoader(),
                new Class<?>[] {Player.class}, (ignored, method, arguments) -> switch (method.getName()) {
                    case "getUniqueId" -> playerId;
                    case "isOnline" -> true;
                    default -> method.getReturnType().isPrimitive() ? primitiveDefault(method.getReturnType()) : null;
                });
    }

    private static Object primitiveDefault(Class<?> type) {
        if (type == boolean.class) return false;
        if (type == char.class) return '\0';
        if (type == byte.class) return (byte) 0;
        if (type == short.class) return (short) 0;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == float.class) return 0F;
        if (type == double.class) return 0D;
        throw new IllegalArgumentException("unknown primitive " + type);
    }

    private static MCAceRuntimeScheduler immediateScheduler() {
        return countingScheduler(null);
    }

    private static MCAceRuntimeScheduler countingScheduler(AtomicInteger scheduled) {
        return new MCAceRuntimeScheduler() {
            @Override public RuntimeFlavor runtimeFlavor() { return RuntimeFlavor.PAPER; }
            @Override public void executeGlobal(Runnable task) { task.run(); }
            @Override public void executeAtRegion(World world, int chunkX, int chunkZ, Runnable task) { task.run(); }
            @Override public void executeForPlayer(Player player, Runnable task, Runnable retired) {
                if (scheduled != null) {
                    scheduled.incrementAndGet();
                }
                task.run();
            }
            @Override public void repeatGlobal(Runnable task, long initialDelayTicks, long periodTicks) { }
            @Override public void close() { }
        };
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
