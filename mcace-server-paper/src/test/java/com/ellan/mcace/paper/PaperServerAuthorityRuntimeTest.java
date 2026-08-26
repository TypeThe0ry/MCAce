package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.authority.BackendAuthorityGrantCodec;
import com.ellan.mcace.core.authority.BackendAuthorityPin;
import com.ellan.mcace.core.authority.BackendAuthorityProfile;
import com.ellan.mcace.paper.behavior.BehaviorAlert;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import com.ellan.mcace.sdk.RiskBand;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import org.bukkit.World;
import org.bukkit.Server;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class PaperServerAuthorityRuntimeTest {
    private static final UUID PLAYER_ID =
            UUID.fromString("00000000-0000-0000-0000-0000000000a1");
    private static final Instant NOW = Instant.parse("2026-08-25T16:00:00Z");
    private static final String SESSION = "authority-runtime-session";

    @TempDir Path directory;

    @BeforeEach
    void useDedicatedPrivateAuthorityDirectory() throws Exception {
        directory = PaperAuthorityTestFiles.privateDirectory(
                directory, "private-paper-runtime-root");
    }

    @Test
    void clientGarbageTamperingAndReplayCannotRevokeTheCurrentVerifiedGrant()
            throws Exception {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        KeyPair proxyIdentity = Ed25519Keys.generate(new SecureRandom());
        KeyPair backendIdentity = Ed25519Keys.generate(new SecureRandom());
        Path journal = directory.resolve("issuance.log");
        PaperAuthorityTestFiles.initializeJournal(journal);
        BackendAuthorityProfile profile = new BackendAuthorityProfile(
                List.of(
                        new BackendAuthorityProfile.ProviderContract(
                                "grim-domain", "grim", "1.0.0", "movement-stable", 1),
                        new BackendAuthorityProfile.ProviderContract(
                                "vulcan-domain", "vulcan", "1.0.0", "movement-stable", 1)),
                2, Duration.ofSeconds(10), Duration.ofSeconds(30));
        PaperServerAuthorityConfiguration configuration =
                new PaperServerAuthorityConfiguration(
                        true, "proxy-1", "paper-1", backendIdentity,
                        BackendAuthorityPin.keyIdFor(backendIdentity.getPublic()), journal,
                        1024L * 1024L, Duration.ofSeconds(10), profile);
        Player player = player();

        try (PaperServerAuthorityRuntime runtime = new PaperServerAuthorityRuntime(
                plugin(), configuration, proxyIdentity.getPublic(), clock,
                new InlineScheduler(), Logger.getLogger("mcace-authority-runtime-test"))) {
            PlayerSecuritySnapshot snapshot = new PlayerSecuritySnapshot(
                    PLAYER_ID, TrustLevel.VERIFIED, AdmissionStatus.VERIFIED, 0,
                    RiskBand.NORMAL, "policy-v1", NOW, List.of());
            runtime.acceptAdmission(player, new PaperAdmissionReceiver.AcceptedAdmission(
                    PLAYER_ID, 41L, NOW.plusSeconds(20), snapshot));

            byte[] binding = new byte[32];
            java.util.Arrays.fill(binding, (byte) 7);
            BackendAuthorityGrantCodec codec =
                    new BackendAuthorityGrantCodec(clock, new SecureRandom());
            byte[] valid = codec.issue(new BackendAuthorityGrantCodec.GrantRequest(
                    "proxy-1", "paper-1", PLAYER_ID, SESSION, binding,
                    41L, 1L, Duration.ofSeconds(20)), proxyIdentity.getPrivate()).frame();
            runtime.onPluginMessageReceived(
                    ProtocolConstants.BACKEND_AUTHORITY_CHANNEL, player, valid);
            runtime.awaitAuthorityWriterForTests(Duration.ofSeconds(5));
            assertEquals(1, runtime.trackedGrants());

            runtime.onPluginMessageReceived(
                    ProtocolConstants.BACKEND_AUTHORITY_CHANNEL, player, new byte[] {1, 2, 3});
            assertEquals(1, runtime.trackedGrants(),
                    "client-originated malformed bytes must not revoke a signed grant");

            byte[] tampered = valid.clone();
            tampered[tampered.length - 1] ^= 1;
            runtime.onPluginMessageReceived(
                    ProtocolConstants.BACKEND_AUTHORITY_CHANNEL, player, tampered);
            assertEquals(1, runtime.trackedGrants(),
                    "a bad signature must not revoke a signed grant");

            runtime.onPluginMessageReceived(
                    ProtocolConstants.BACKEND_AUTHORITY_CHANNEL, player, valid);
            assertEquals(1, runtime.trackedGrants(),
                    "a replayed valid frame must not revoke the newer current state");
        }
    }

    @Test
    void providerSchedulerFailureNeverEscapesTheProviderCallback() throws Exception {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        KeyPair proxyIdentity = Ed25519Keys.generate(new SecureRandom());
        KeyPair backendIdentity = Ed25519Keys.generate(new SecureRandom());
        Path journal = directory.resolve("provider-failure-issuance.log");
        PaperAuthorityTestFiles.initializeJournal(journal);
        BackendAuthorityProfile profile = new BackendAuthorityProfile(
                List.of(
                        new BackendAuthorityProfile.ProviderContract(
                                "grim-domain", "grim", "1.0.0", "movement-stable", 1),
                        new BackendAuthorityProfile.ProviderContract(
                                "vulcan-domain", "vulcan", "1.0.0", "movement-stable", 1)),
                2, Duration.ofSeconds(10), Duration.ofSeconds(30));
        PaperServerAuthorityConfiguration configuration =
                new PaperServerAuthorityConfiguration(
                        true, "proxy-1", "paper-1", backendIdentity,
                        BackendAuthorityPin.keyIdFor(backendIdentity.getPublic()), journal,
                        1024L * 1024L, Duration.ofSeconds(10), profile);
        Player player = player();

        try (PaperServerAuthorityRuntime runtime = new PaperServerAuthorityRuntime(
                plugin(player), configuration, proxyIdentity.getPublic(), clock,
                new RejectingScheduler(), Logger.getLogger("mcace-provider-failure-test"))) {
            BehaviorAlert alert = new BehaviorAlert(
                    PLAYER_ID, BehaviorAlert.providerEventIdSha256(
                            "grim", PLAYER_ID.toString(), "provider-failure"),
                    "grim", "1.0.0", "raw-check", "movement-stable",
                    1.0D, false, NOW);
            assertDoesNotThrow(() -> runtime.accept(player, alert));
        }
    }

    @Test
    void restartRecoversTheExactDurableCooldownBeforeSendingAgain() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        KeyPair proxyIdentity = Ed25519Keys.generate(new SecureRandom());
        KeyPair backendIdentity = Ed25519Keys.generate(new SecureRandom());
        Path journal = directory.resolve("restart-cooldown-issuance.log");
        PaperAuthorityTestFiles.initializeJournal(journal);
        BackendAuthorityProfile profile = new BackendAuthorityProfile(
                List.of(
                        new BackendAuthorityProfile.ProviderContract(
                                "grim-domain", "grim", "1.0.0", "movement-stable", 1),
                        new BackendAuthorityProfile.ProviderContract(
                                "vulcan-domain", "vulcan", "1.0.0", "movement-stable", 1)),
                2, Duration.ofSeconds(10), Duration.ofSeconds(10));
        PaperServerAuthorityConfiguration configuration =
                new PaperServerAuthorityConfiguration(
                        true, "proxy-1", "paper-1", backendIdentity,
                        BackendAuthorityPin.keyIdFor(backendIdentity.getPublic()), journal,
                        1024L * 1024L, Duration.ofSeconds(10), profile);
        PlayerHarness harness = playerHarness();
        byte[] binding = new byte[32];
        java.util.Arrays.fill(binding, (byte) 7);

        try (PaperServerAuthorityRuntime first = new PaperServerAuthorityRuntime(
                plugin(harness.player()), configuration, proxyIdentity.getPublic(), clock,
                new InlineScheduler(), Logger.getLogger("mcace-restart-cooldown-first"))) {
            admitAndGrant(first, harness.player(), proxyIdentity, clock, binding);
            first.accept(harness.player(), providerAlert("grim", clock.instant()));
            first.accept(harness.player(), providerAlert("vulcan", clock.instant()));
            first.awaitAuthorityWriterForTests(Duration.ofSeconds(5));
            assertEquals(1, harness.frames().size());
        }

        clock.set(NOW.plusSeconds(5));
        try (PaperServerAuthorityRuntime restarted = new PaperServerAuthorityRuntime(
                plugin(harness.player()), configuration, proxyIdentity.getPublic(), clock,
                new InlineScheduler(), Logger.getLogger("mcace-restart-cooldown-second"))) {
            admitAndGrant(restarted, harness.player(), proxyIdentity, clock, binding);
            restarted.accept(harness.player(), providerAlert("grim", clock.instant()));
            restarted.accept(harness.player(), providerAlert("vulcan", clock.instant()));
            restarted.awaitAuthorityWriterForTests(Duration.ofSeconds(5));
            assertEquals(1, harness.frames().size(),
                    "restart cannot erase the durable issuance cooldown");

            clock.set(NOW.plusSeconds(10));
            restarted.accept(harness.player(), providerAlert("grim", clock.instant()));
            restarted.awaitAuthorityWriterForTests(Duration.ofSeconds(5));
            assertEquals(2, harness.frames().size(),
                    "publication becomes eligible exactly at durable issuedAt plus cooldown");
        }
    }

    @Test
    void providerThresholdAccumulatesAcrossRoutineFiveSecondAdmissionRefresh()
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        KeyPair proxyIdentity = Ed25519Keys.generate(new SecureRandom());
        KeyPair backendIdentity = Ed25519Keys.generate(new SecureRandom());
        Path journal = directory.resolve("routine-refresh-issuance.log");
        PaperAuthorityTestFiles.initializeJournal(journal);
        BackendAuthorityProfile profile = new BackendAuthorityProfile(
                List.of(
                        new BackendAuthorityProfile.ProviderContract(
                                "grim-domain", "grim", "1.0.0", "movement-stable", 2),
                        new BackendAuthorityProfile.ProviderContract(
                                "vulcan-domain", "vulcan", "1.0.0", "movement-stable", 2)),
                2, Duration.ofSeconds(10), Duration.ZERO);
        PaperServerAuthorityConfiguration configuration =
                new PaperServerAuthorityConfiguration(
                        true, "proxy-1", "paper-1", backendIdentity,
                        BackendAuthorityPin.keyIdFor(backendIdentity.getPublic()), journal,
                        1024L * 1024L, Duration.ofSeconds(10), profile);
        PlayerHarness harness = playerHarness();
        byte[] binding = new byte[32];
        java.util.Arrays.fill(binding, (byte) 7);

        try (PaperServerAuthorityRuntime runtime = new PaperServerAuthorityRuntime(
                plugin(harness.player()), configuration, proxyIdentity.getPublic(), clock,
                new InlineScheduler(), Logger.getLogger("mcace-routine-refresh-test"))) {
            admitAndGrant(runtime, harness.player(), proxyIdentity, clock, binding);
            Player retiredCarrier = player();
            runtime.accept(retiredCarrier, providerAlert("grim", clock.instant()));
            runtime.accept(retiredCarrier, providerAlert("vulcan", clock.instant()));
            assertEquals(0, harness.frames().size(),
                    "same-UUID callbacks from a retired Player capability must be ignored");
            runtime.accept(harness.player(), providerAlert("grim", clock.instant()));
            runtime.accept(harness.player(), providerAlert("vulcan", clock.instant()));
            assertEquals(0, harness.frames().size());

            clock.set(NOW.plusSeconds(5));
            PlayerSecuritySnapshot refreshed = new PlayerSecuritySnapshot(
                    PLAYER_ID, TrustLevel.VERIFIED, AdmissionStatus.VERIFIED, 0,
                    RiskBand.NORMAL, "policy-v1", clock.instant(), List.of());
            runtime.acceptAdmission(harness.player(), new PaperAdmissionReceiver.AcceptedAdmission(
                    PLAYER_ID, 42L, clock.instant().plusSeconds(20), refreshed));
            runtime.accept(harness.player(), providerAlert("grim", clock.instant()));
            runtime.accept(harness.player(), providerAlert("vulcan", clock.instant()));
            runtime.awaitAuthorityWriterForTests(Duration.ofSeconds(5));

            assertEquals(1, harness.frames().size(),
                    "routine admission refresh must not reset the same-lifecycle provider window");
        }
    }

    @Test
    void grantRecoveryRunsOnTheWriterAndSupersedesAnOlderDeferredSendSafely()
            throws Exception {
        MutableClock clock = new MutableClock(NOW);
        KeyPair proxyIdentity = Ed25519Keys.generate(new SecureRandom());
        KeyPair backendIdentity = Ed25519Keys.generate(new SecureRandom());
        Path journal = directory.resolve("async-grant-recovery-issuance.log");
        PaperAuthorityTestFiles.initializeJournal(journal);
        BackendAuthorityProfile profile = new BackendAuthorityProfile(
                List.of(
                        new BackendAuthorityProfile.ProviderContract(
                                "grim-domain", "grim", "1.0.0", "movement-stable", 1),
                        new BackendAuthorityProfile.ProviderContract(
                                "vulcan-domain", "vulcan", "1.0.0", "movement-stable", 1)),
                2, Duration.ofSeconds(10), Duration.ZERO);
        PaperServerAuthorityConfiguration configuration =
                new PaperServerAuthorityConfiguration(
                        true, "proxy-1", "paper-1", backendIdentity,
                        BackendAuthorityPin.keyIdFor(backendIdentity.getPublic()), journal,
                        1024L * 1024L, Duration.ofSeconds(10), profile);
        PlayerHarness harness = playerHarness();
        DeferredWriterCompletionScheduler scheduler =
                new DeferredWriterCompletionScheduler();
        byte[] binding = new byte[32];
        java.util.Arrays.fill(binding, (byte) 7);
        BackendAuthorityGrantCodec codec =
                new BackendAuthorityGrantCodec(clock, new SecureRandom());

        try (PaperServerAuthorityRuntime runtime = new PaperServerAuthorityRuntime(
                plugin(harness.player()), configuration, proxyIdentity.getPublic(), clock,
                scheduler, Logger.getLogger("mcace-async-grant-recovery-test"))) {
            PlayerSecuritySnapshot initial = new PlayerSecuritySnapshot(
                    PLAYER_ID, TrustLevel.VERIFIED, AdmissionStatus.VERIFIED, 0,
                    RiskBand.NORMAL, "policy-v1", clock.instant(), List.of());
            runtime.acceptAdmission(harness.player(), new PaperAdmissionReceiver.AcceptedAdmission(
                    PLAYER_ID, 41L, clock.instant().plusSeconds(20), initial));
            byte[] firstGrant = codec.issue(new BackendAuthorityGrantCodec.GrantRequest(
                    "proxy-1", "paper-1", PLAYER_ID, SESSION, binding,
                    41L, 1L, Duration.ofSeconds(20)), proxyIdentity.getPrivate()).frame();
            runtime.onPluginMessageReceived(
                    ProtocolConstants.BACKEND_AUTHORITY_CHANNEL,
                    harness.player(), firstGrant);
            runtime.awaitAuthorityWriterForTests(Duration.ofSeconds(5));
            scheduler.runOldest();
            assertEquals(1L, runtime.currentGrantSequenceForTests(PLAYER_ID));

            CountDownLatch writerStarted = new CountDownLatch(1);
            CountDownLatch releaseWriter = new CountDownLatch(1);
            runtime.executeAuthorityWriterForTests(() -> {
                writerStarted.countDown();
                try {
                    if (!releaseWriter.await(5, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("timed out waiting to release writer");
                    }
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("writer blocker interrupted", exception);
                }
            });
            assertTrue(writerStarted.await(5, TimeUnit.SECONDS));

            runtime.accept(harness.player(), providerAlert("grim", clock.instant()));
            runtime.accept(harness.player(), providerAlert("vulcan", clock.instant()));

            clock.set(NOW.plusSeconds(1));
            PlayerSecuritySnapshot refreshed = new PlayerSecuritySnapshot(
                    PLAYER_ID, TrustLevel.VERIFIED, AdmissionStatus.VERIFIED, 0,
                    RiskBand.NORMAL, "policy-v1", clock.instant(), List.of());
            runtime.acceptAdmission(harness.player(), new PaperAdmissionReceiver.AcceptedAdmission(
                    PLAYER_ID, 42L, clock.instant().plusSeconds(20), refreshed));
            byte[] secondGrant = codec.issue(new BackendAuthorityGrantCodec.GrantRequest(
                    "proxy-1", "paper-1", PLAYER_ID, SESSION, binding,
                    42L, 2L, Duration.ofSeconds(19)), proxyIdentity.getPrivate()).frame();
            runtime.onPluginMessageReceived(
                    ProtocolConstants.BACKEND_AUTHORITY_CHANNEL,
                    harness.player(), secondGrant);

            releaseWriter.countDown();
            runtime.awaitAuthorityWriterForTests(Duration.ofSeconds(5));
            assertEquals(2, scheduler.deferredTasks());

            // Exercise the adverse scheduler ordering: the newer grant recovery callback runs
            // before the older durable send callback. The new grant must remain installed and
            // the retired frame must not be sent under the superseded capability.
            scheduler.runNewest();
            scheduler.runOldest();
            assertEquals(2L, runtime.currentGrantSequenceForTests(PLAYER_ID));
            assertEquals(1, runtime.trackedGrants());
            assertEquals(0, harness.frames().size());

            clock.set(NOW.plusSeconds(2));
            runtime.accept(harness.player(), providerAlert("grim", clock.instant()));
            runtime.accept(harness.player(), providerAlert("vulcan", clock.instant()));
            runtime.awaitAuthorityWriterForTests(Duration.ofSeconds(5));
            scheduler.runOldest();
            assertEquals(1, harness.frames().size(),
                    "the recovered sequence must remain usable under the newer grant");
        }
    }

    private static void admitAndGrant(
            PaperServerAuthorityRuntime runtime,
            Player player,
            KeyPair proxyIdentity,
            Clock clock,
            byte[] binding) throws Exception {
        Instant now = clock.instant();
        PlayerSecuritySnapshot snapshot = new PlayerSecuritySnapshot(
                PLAYER_ID, TrustLevel.VERIFIED, AdmissionStatus.VERIFIED, 0,
                RiskBand.NORMAL, "policy-v1", now, List.of());
        runtime.acceptAdmission(player, new PaperAdmissionReceiver.AcceptedAdmission(
                PLAYER_ID, 41L, now.plusSeconds(20), snapshot));
        BackendAuthorityGrantCodec codec =
                new BackendAuthorityGrantCodec(clock, new SecureRandom());
        byte[] grant = codec.issue(new BackendAuthorityGrantCodec.GrantRequest(
                "proxy-1", "paper-1", PLAYER_ID, SESSION, binding,
                41L, 1L, Duration.ofSeconds(20)), proxyIdentity.getPrivate()).frame();
        runtime.onPluginMessageReceived(
                ProtocolConstants.BACKEND_AUTHORITY_CHANNEL, player, grant);
        runtime.awaitAuthorityWriterForTests(Duration.ofSeconds(5));
        assertEquals(1, runtime.trackedGrants());
    }

    private static BehaviorAlert providerAlert(String provider, Instant observedAt) {
        return new BehaviorAlert(
                PLAYER_ID, BehaviorAlert.providerEventIdSha256(
                        provider, PLAYER_ID.toString(), observedAt.toString(),
                        UUID.randomUUID().toString()),
                provider, "1.0.0", "raw-check", "movement-stable",
                1.0D, false, observedAt);
    }

    private static Player player() {
        return (Player) Proxy.newProxyInstance(
                PaperServerAuthorityRuntimeTest.class.getClassLoader(),
                new Class<?>[] {Player.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "getUniqueId" -> PLAYER_ID;
                    case "isOnline" -> true;
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == arguments[0];
                    case "toString" -> "authority-test-player";
                    default -> primitiveDefault(method.getReturnType());
                });
    }

    private static PlayerHarness playerHarness() {
        List<byte[]> frames = new ArrayList<>();
        Player player = (Player) Proxy.newProxyInstance(
                PaperServerAuthorityRuntimeTest.class.getClassLoader(),
                new Class<?>[] {Player.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "getUniqueId" -> PLAYER_ID;
                    case "isOnline" -> true;
                    case "getListeningPluginChannels" ->
                            Set.of(ProtocolConstants.BACKEND_AUTHORITY_CHANNEL);
                    case "sendPluginMessage" -> {
                        frames.add(((byte[]) arguments[2]).clone());
                        yield null;
                    }
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == arguments[0];
                    case "toString" -> "authority-cooldown-player";
                    default -> primitiveDefault(method.getReturnType());
                });
        return new PlayerHarness(player, frames);
    }

    private static Plugin plugin() {
        return (Plugin) Proxy.newProxyInstance(
                PaperServerAuthorityRuntimeTest.class.getClassLoader(),
                new Class<?>[] {Plugin.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == arguments[0];
                    case "toString" -> "authority-test-plugin";
                    default -> primitiveDefault(method.getReturnType());
                });
    }

    private static Plugin plugin(Player player) {
        Server server = (Server) Proxy.newProxyInstance(
                PaperServerAuthorityRuntimeTest.class.getClassLoader(),
                new Class<?>[] {Server.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "getPlayer" -> player;
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == arguments[0];
                    case "toString" -> "authority-test-server";
                    default -> primitiveDefault(method.getReturnType());
                });
        return (Plugin) Proxy.newProxyInstance(
                PaperServerAuthorityRuntimeTest.class.getClassLoader(),
                new Class<?>[] {Plugin.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "getServer" -> server;
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == arguments[0];
                    case "toString" -> "authority-test-plugin";
                    default -> primitiveDefault(method.getReturnType());
                });
    }

    private static Object primitiveDefault(Class<?> type) {
        if (!type.isPrimitive() || type == void.class) return null;
        if (type == boolean.class) return false;
        if (type == char.class) return '\0';
        if (type == byte.class) return (byte) 0;
        if (type == short.class) return (short) 0;
        if (type == int.class) return 0;
        if (type == long.class) return 0L;
        if (type == float.class) return 0.0F;
        return 0.0D;
    }

    private static final class InlineScheduler implements MCAceRuntimeScheduler {
        @Override public RuntimeFlavor runtimeFlavor() { return RuntimeFlavor.PAPER; }
        @Override public void executeGlobal(Runnable task) { task.run(); }
        @Override public void executeAtRegion(
                World world, int chunkX, int chunkZ, Runnable task) { task.run(); }
        @Override public void executeForPlayer(
                Player player, Runnable task, Runnable retired) { task.run(); }
        @Override public void repeatGlobal(
                Runnable task, long initialDelayTicks, long periodTicks) { }
        @Override public void close() { }
    }

    private static final class DeferredWriterCompletionScheduler
            implements MCAceRuntimeScheduler {
        private final Thread owner = Thread.currentThread();
        private final List<Runnable> deferred = new ArrayList<>();

        @Override public RuntimeFlavor runtimeFlavor() { return RuntimeFlavor.PAPER; }
        @Override public void executeGlobal(Runnable task) { task.run(); }
        @Override public void executeAtRegion(
                World world, int chunkX, int chunkZ, Runnable task) { task.run(); }
        @Override public void executeForPlayer(
                Player player, Runnable task, Runnable retired) {
            if (Thread.currentThread() == owner) {
                task.run();
                return;
            }
            synchronized (deferred) {
                deferred.add(task);
            }
        }
        @Override public void repeatGlobal(
                Runnable task, long initialDelayTicks, long periodTicks) { }
        @Override public void close() { }

        private int deferredTasks() {
            synchronized (deferred) {
                return deferred.size();
            }
        }

        private void runOldest() {
            Runnable task;
            synchronized (deferred) {
                task = deferred.remove(0);
            }
            task.run();
        }

        private void runNewest() {
            Runnable task;
            synchronized (deferred) {
                task = deferred.remove(deferred.size() - 1);
            }
            task.run();
        }
    }

    private static final class RejectingScheduler implements MCAceRuntimeScheduler {
        @Override public RuntimeFlavor runtimeFlavor() { return RuntimeFlavor.PAPER; }
        @Override public void executeGlobal(Runnable task) { throw new IllegalStateException("rejected"); }
        @Override public void executeAtRegion(
                World world, int chunkX, int chunkZ, Runnable task) {
            throw new IllegalStateException("rejected");
        }
        @Override public void executeForPlayer(
                Player player, Runnable task, Runnable retired) {
            throw new IllegalStateException("rejected");
        }
        @Override public void repeatGlobal(
                Runnable task, long initialDelayTicks, long periodTicks) { }
        @Override public void close() { }
    }

    private record PlayerHarness(Player player, List<byte[]> frames) {
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        private MutableClock(Instant now) {
            this.now = now;
        }

        private void set(Instant value) {
            now = value;
        }

        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
