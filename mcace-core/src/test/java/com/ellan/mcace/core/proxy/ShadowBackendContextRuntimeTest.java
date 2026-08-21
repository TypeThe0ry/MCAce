package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.context.BackendContextCodec;
import com.ellan.mcace.core.context.BackendContextReport;
import com.ellan.mcace.core.session.AuthenticatedManifest;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.AuthRequest;
import com.ellan.mcace.protocol.generated.FileEntry;
import com.ellan.mcace.protocol.generated.IntegrityScopeManifest;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.core.disposition.DispositionAction;
import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class ShadowBackendContextRuntimeTest {
    private static final Instant NOW = Instant.parse("2026-08-12T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final String SESSION = "session-123456789012";

    @Test
    void sourceBackendAndBoundedOutstandingAdmissionSequencesGateAnAuditOnlyEvaluation() throws Exception {
        KeyPair keyPair = Ed25519Keys.generate(new SecureRandom());
        SharedProxyDispositionPolicyRuntime policy = new SharedProxyDispositionPolicyRuntime(
                ProxyFamily.VELOCITY, () -> null, keyPair.getPublic(), CLOCK, Duration.ofSeconds(30));
        CountDownLatch audited = new CountDownLatch(1);
        AtomicReference<ShadowBackendContextAuditRecord> captured = new AtomicReference<>();
        try (ShadowBackendContextRuntime runtime = new ShadowBackendContextRuntime(
                "velocity", new AuthenticatedManifestObservationDeriver(), policy, CLOCK,
                record -> {
                    captured.set(record);
                    audited.countDown();
                })) {
            runtime.rememberManifest(manifest());
            // A periodic sweep may run while Velocity/Folia is still completing the play join.
            // It must not erase the authenticated manifest before the first backend binding exists.
            runtime.expire();
            runtime.expectBackend(PLAYER, SESSION, "survival", 41L, NOW.plusSeconds(15));
            runtime.expectBackend(PLAYER, SESSION, "survival", 42L, NOW.plusSeconds(15));
            runtime.expectBackend(PLAYER, SESSION, "survival", 43L, NOW.plusSeconds(15));
            byte[] frame = frame(41L, 1L);

            ShadowBackendContextRuntime.ReceiveResult accepted =
                    runtime.receive(PLAYER, "survival", frame);

            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.ACCEPTED_QUEUED, accepted.status());
            assertTrue(audited.await(2, TimeUnit.SECONDS));
            assertEquals("survival", captured.get().backendId());
            assertEquals("minecraft:overworld", captured.get().worldId());
            assertEquals("survival", captured.get().gameMode());
            assertEquals(1, captured.get().observationCount());
            assertEquals(1, captured.get().actionCounts().get(DispositionAction.OBSERVE));
            assertEquals(ProxyPolicyRefreshStatus.OBSERVE_NO_VALID_POLICY, captured.get().policyStatus());
            assertTrue(runtime.current(PLAYER).isPresent());
            assertEquals(41L, runtime.current(PLAYER).orElseThrow().admissionTransportSequence());

            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.REJECTED_REPLAY,
                    runtime.receive(PLAYER, "survival", frame).status());
            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.REJECTED_BINDING,
                    runtime.receive(PLAYER, "creative", frame(41L, 2L)).status());
            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.REJECTED_BINDING,
                    runtime.receive(UUID.randomUUID(), "survival", frame(41L, 2L)).status());
            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.ACCEPTED_QUEUED,
                    runtime.receive(PLAYER, "survival", frame(41L, 2L)).status());
            assertEquals(41L, runtime.current(PLAYER).orElseThrow().admissionTransportSequence());
            assertEquals(2L, runtime.current(PLAYER).orElseThrow().reportSequence());

            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.ACCEPTED_QUEUED,
                    runtime.receive(PLAYER, "survival", frame(43L, 3L)).status());
            assertEquals(43L, runtime.current(PLAYER).orElseThrow().admissionTransportSequence());
            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.REJECTED_BINDING,
                    runtime.receive(PLAYER, "survival", frame(41L, 4L)).status());
            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.REJECTED_BINDING,
                    runtime.receive(PLAYER, "survival", frame(42L, 4L)).status());
            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.REJECTED_BINDING,
                    runtime.receive(PLAYER, "survival", frame(44L, 4L)).status());

            runtime.expectBackend(
                    PLAYER, "replacement-session", "survival", 50L, NOW.plusSeconds(15));
            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.REJECTED_BINDING,
                    runtime.receive(PLAYER, "survival", frame(43L, 4L)).status());
            runtime.expectBackend(
                    PLAYER, "replacement-session", "creative", 51L, NOW.plusSeconds(15));
            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.REJECTED_BINDING,
                    runtime.receive(PLAYER, "survival", frame(50L, 4L)).status());
            runtime.clear(PLAYER);
            assertFalse(runtime.current(PLAYER).isPresent());
        }
    }

    @Test
    void outstandingAdmissionWindowIsBoundedAndExpiredEntriesCannotBind() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        KeyPair keyPair = Ed25519Keys.generate(new SecureRandom());
        SharedProxyDispositionPolicyRuntime policy = new SharedProxyDispositionPolicyRuntime(
                ProxyFamily.BUNGEECORD, () -> null, keyPair.getPublic(), clock, Duration.ofSeconds(30));
        try (ShadowBackendContextRuntime runtime = new ShadowBackendContextRuntime(
                "bungeecord", new AuthenticatedManifestObservationDeriver(), policy, clock,
                record -> { })) {
            for (long sequence = 100L; sequence <= 108L; sequence++) {
                runtime.expectBackend(
                        PLAYER, SESSION, "survival", sequence, clock.instant().plusSeconds(15));
            }
            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.REJECTED_BINDING,
                    runtime.receive(PLAYER, "survival", frame(clock, 100L, 1L)).status());
            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.ACCEPTED_NO_MANIFEST,
                    runtime.receive(PLAYER, "survival", frame(clock, 101L, 1L)).status());

            runtime.expectBackend(
                    PLAYER, SESSION, "survival", 109L, clock.instant().plusSeconds(15));
            clock.advance(Duration.ofSeconds(15).plusMillis(1L));
            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.REJECTED_BINDING,
                    runtime.receive(PLAYER, "survival", frame(clock, 109L, 2L)).status());
        }
    }

    @Test
    void outstandingAdmissionsExpireAtTheirIndependentSignedDeadlines() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        KeyPair keyPair = Ed25519Keys.generate(new SecureRandom());
        SharedProxyDispositionPolicyRuntime policy = new SharedProxyDispositionPolicyRuntime(
                ProxyFamily.BUNGEECORD, () -> null, keyPair.getPublic(), clock, Duration.ofSeconds(30));
        try (ShadowBackendContextRuntime runtime = new ShadowBackendContextRuntime(
                "bungeecord", new AuthenticatedManifestObservationDeriver(), policy, clock,
                record -> { })) {
            runtime.expectBackend(
                    PLAYER, SESSION, "survival", 100L, clock.instant().plusSeconds(15));
            clock.advance(Duration.ofSeconds(5));
            runtime.expectBackend(
                    PLAYER, SESSION, "survival", 101L, clock.instant().plusSeconds(15));
            clock.advance(Duration.ofSeconds(5));
            runtime.expectBackend(
                    PLAYER, SESSION, "survival", 102L, clock.instant().plusSeconds(15));
            clock.advance(Duration.ofSeconds(6));

            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.REJECTED_BINDING,
                    runtime.receive(PLAYER, "survival", frame(clock, 100L, 1L)).status());
            assertEquals(ShadowBackendContextRuntime.ReceiveStatus.ACCEPTED_NO_MANIFEST,
                    runtime.receive(PLAYER, "survival", frame(clock, 101L, 1L)).status());
        }
    }

    private static AuthenticatedManifest manifest() {
        return new AuthenticatedManifest(
                PLAYER, SESSION, SecurityPolicy.getDefaultInstance(), AuthRequest.newBuilder()
                        .addScopeManifests(IntegrityScopeManifest.newBuilder()
                                .setScope("config")
                                .setPresent(true)
                                .addEntries(FileEntry.newBuilder()
                                        .setRelativePath("options.txt")
                                        .setFileSize(12L)
                                        .setSha256(ByteString.copyFrom(new byte[32]))))
                        .build(), NOW);
    }

    private static byte[] frame(long admissionSequence, long reportSequence) throws Exception {
        return frame(CLOCK, admissionSequence, reportSequence);
    }

    private static byte[] frame(
            Clock clock, long admissionSequence, long reportSequence) throws Exception {
        return new BackendContextCodec(clock).encode(new BackendContextReport(
                PLAYER, admissionSequence, reportSequence,
                "minecraft:overworld", "survival", clock.instant()));
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        private MutableClock(Instant now) {
            this.now = now;
        }

        private void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) {
                throw new IllegalArgumentException("test clock supports UTC only");
            }
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
