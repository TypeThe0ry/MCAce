package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.authority.AuthorityProtocolException;
import com.ellan.mcace.core.authority.AuthoritySequenceMismatchException;
import com.ellan.mcace.core.authority.BackendAuthorityGrantCodec;
import com.ellan.mcace.core.authority.BackendAuthorityPin;
import com.ellan.mcace.core.authority.DurableServerAuthorityIssuer;
import com.ellan.mcace.core.authority.DurablyIssuedServerAuthorityObservation;
import com.ellan.mcace.core.authority.ServerAuthorityJournalPreflight;
import com.ellan.mcace.core.authority.ServerAuthorityObservationCodec;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class PaperServerAuthorityIssueCoordinatorTest {
    private static final Instant NOW = Instant.parse("2026-08-13T00:00:00Z");
    private static final UUID PLAYER =
            UUID.fromString("00000000-0000-0000-0000-000000000071");
    private static final String SESSION = "authority-session";
    private static final String PROFILE = "ab".repeat(32);

    @TempDir Path directory;

    @Test
    void returnsTheFrameOnlyAfterExactDurableCommitAndRejectsPreJournalDrift()
            throws Exception {
        KeyPair backendKeys = Ed25519Keys.generate(new SecureRandom());
        BackendAuthorityGrantCodec.VerifiedGrant grant = grant(Duration.ofSeconds(20));
        try (TestAuthority authority = TestAuthority.create(
                directory.resolve("coordinator.log"), backendKeys)) {
            PaperServerAuthorityLifecycle lifecycle = PaperServerAuthorityLifecycle.enabledForTests(
                    Clock.fixed(NOW, ZoneOffset.UTC));
            assertTrue(lifecycle.acceptVerifiedGrant(
                    PLAYER, grant, authority.issuer().recover(grant)));
            PaperServerAuthorityIssueCoordinator coordinator =
                    new PaperServerAuthorityIssueCoordinator(lifecycle, authority.issuer());

            List<ServerAuthorityObservationCodec.ObservationRequest> mismatches =
                    new ArrayList<>();
            mismatches.add(request(grant, backendKeys, 1L, Duration.ofSeconds(5),
                    "other-backend", PLAYER, SESSION, grant.grantId(),
                    grant.commitmentSha256(), grant.physicalLoginBinding(),
                    grant.admissionTransportSequence(), NOW));
            mismatches.add(request(grant, backendKeys, 1L, Duration.ofSeconds(5),
                    grant.backendInstanceId(), UUID.randomUUID(), SESSION, grant.grantId(),
                    grant.commitmentSha256(), grant.physicalLoginBinding(),
                    grant.admissionTransportSequence(), NOW));
            mismatches.add(request(grant, backendKeys, 1L, Duration.ofSeconds(5),
                    grant.backendInstanceId(), PLAYER, "other-session", grant.grantId(),
                    grant.commitmentSha256(), grant.physicalLoginBinding(),
                    grant.admissionTransportSequence(), NOW));
            mismatches.add(request(grant, backendKeys, 1L, Duration.ofSeconds(5),
                    grant.backendInstanceId(), PLAYER, SESSION, UUID.randomUUID(),
                    grant.commitmentSha256(), grant.physicalLoginBinding(),
                    grant.admissionTransportSequence(), NOW));
            mismatches.add(request(grant, backendKeys, 1L, Duration.ofSeconds(5),
                    grant.backendInstanceId(), PLAYER, SESSION, grant.grantId(),
                    "cd".repeat(32), grant.physicalLoginBinding(),
                    grant.admissionTransportSequence(), NOW));
            mismatches.add(request(grant, backendKeys, 1L, Duration.ofSeconds(5),
                    grant.backendInstanceId(), PLAYER, SESSION, grant.grantId(),
                    grant.commitmentSha256(), filledBinding((byte) 9),
                    grant.admissionTransportSequence(), NOW));
            mismatches.add(request(grant, backendKeys, 1L, Duration.ofSeconds(5),
                    grant.backendInstanceId(), PLAYER, SESSION, grant.grantId(),
                    grant.commitmentSha256(), grant.physicalLoginBinding(),
                    grant.admissionTransportSequence() + 1L, NOW));
            mismatches.add(request(grant, backendKeys, 2L, Duration.ofSeconds(5),
                    grant.backendInstanceId(), PLAYER, SESSION, grant.grantId(),
                    grant.commitmentSha256(), grant.physicalLoginBinding(),
                    grant.admissionTransportSequence(), NOW));
            mismatches.add(request(grant, backendKeys, 1L, Duration.ofSeconds(5),
                    grant.backendInstanceId(), PLAYER, SESSION, grant.grantId(),
                    grant.commitmentSha256(), grant.physicalLoginBinding(),
                    grant.admissionTransportSequence(), NOW.minusMillis(1L)));
            mismatches.add(request(grant, Ed25519Keys.generate(new SecureRandom()),
                    1L, Duration.ofSeconds(5)));

            for (ServerAuthorityObservationCodec.ObservationRequest mismatch : mismatches) {
                assertThrows(AuthorityProtocolException.class,
                        () -> coordinator.issue(PLAYER, mismatch));
                assertFalse(coordinator.poisoned());
                assertEquals(0L, authority.issuer().recover(grant).lastSequence());
            }

            ServerAuthorityObservationCodec.ObservationRequest correct =
                    request(grant, backendKeys, 1L, Duration.ofSeconds(5));
            DurablyIssuedServerAuthorityObservation issued =
                    coordinator.issue(PLAYER, correct).orElseThrow();
            assertTrue(issued.matches(grant));
            assertEquals(1L, issued.observationSequence());
            assertTrue(issued.signedFrameSha256().matches("[0-9a-f]{64}"));
            assertEquals(1L, authority.issuer().recover(grant).lastSequence());
            assertFalse(coordinator.poisoned());
        }
    }

    @Test
    void durableSequenceDriftDropsStaleLifecycleBeforeAnySecondAppend()
            throws Exception {
        KeyPair backendKeys = Ed25519Keys.generate(new SecureRandom());
        BackendAuthorityGrantCodec.VerifiedGrant grant = grant(Duration.ofSeconds(20));
        try (TestAuthority authority = TestAuthority.create(
                directory.resolve("sequence-drift.log"), backendKeys)) {
            PaperServerAuthorityLifecycle lifecycle = PaperServerAuthorityLifecycle.enabledForTests(
                    Clock.fixed(NOW, ZoneOffset.UTC));
            assertTrue(lifecycle.acceptVerifiedGrant(
                    PLAYER, grant, authority.issuer().recover(grant)));
            PaperServerAuthorityIssueCoordinator coordinator =
                    new PaperServerAuthorityIssueCoordinator(lifecycle, authority.issuer());

            ServerAuthorityObservationCodec.ObservationRequest first =
                    request(grant, backendKeys, 1L, Duration.ofSeconds(5));
            assertEquals(1L, authority.issuer().issue(grant, 1L, first)
                    .observationSequence());
            assertThrows(AuthoritySequenceMismatchException.class,
                    () -> coordinator.issue(PLAYER, first));
            assertFalse(coordinator.poisoned());
            assertEquals(0, lifecycle.trackedPlayers());
            assertEquals(1L, authority.issuer().recover(grant).lastSequence());
        }
    }

    @Test
    void issuerIoFailureReturnsNoFrameAndPermanentlyPoisonsTheCoordinator()
            throws Exception {
        KeyPair backendKeys = Ed25519Keys.generate(new SecureRandom());
        BackendAuthorityGrantCodec.VerifiedGrant grant = grant(Duration.ofSeconds(20));
        try (TestAuthority authority = TestAuthority.create(
                directory.resolve("closed-issuer.log"), backendKeys)) {
            PaperServerAuthorityLifecycle lifecycle = PaperServerAuthorityLifecycle.enabledForTests(
                    Clock.fixed(NOW, ZoneOffset.UTC));
            assertTrue(lifecycle.acceptVerifiedGrant(
                    PLAYER, grant, authority.issuer().recover(grant)));
            PaperServerAuthorityIssueCoordinator coordinator =
                    new PaperServerAuthorityIssueCoordinator(lifecycle, authority.issuer());
            authority.issuer().close();

            ServerAuthorityObservationCodec.ObservationRequest request =
                    request(grant, backendKeys, 1L, Duration.ofSeconds(5));
            assertThrows(IOException.class, () -> coordinator.issue(PLAYER, request));
            assertTrue(coordinator.poisoned());
            assertEquals(0, lifecycle.trackedPlayers());
            assertThrows(IOException.class, () -> coordinator.issue(PLAYER, request));
        }
    }

    @Test
    void grantWindowMismatchFailsBeforeJournalAndLeavesTheLeaseRetryable()
            throws Exception {
        KeyPair backendKeys = Ed25519Keys.generate(new SecureRandom());
        BackendAuthorityGrantCodec.VerifiedGrant grant = grant(Duration.ofSeconds(5));
        try (TestAuthority authority = TestAuthority.create(
                directory.resolve("commit-rejected.log"), backendKeys)) {
            PaperServerAuthorityLifecycle lifecycle = PaperServerAuthorityLifecycle.enabledForTests(
                    Clock.fixed(NOW, ZoneOffset.UTC));
            assertTrue(lifecycle.acceptVerifiedGrant(
                    PLAYER, grant, authority.issuer().recover(grant)));
            PaperServerAuthorityIssueCoordinator coordinator =
                    new PaperServerAuthorityIssueCoordinator(lifecycle, authority.issuer());

            // The computed frame expiry exceeds the exact grant and must be rejected pre-journal.
            ServerAuthorityObservationCodec.ObservationRequest overlong =
                    request(grant, backendKeys, 1L, Duration.ofSeconds(10));
            assertThrows(AuthorityProtocolException.class,
                    () -> coordinator.issue(PLAYER, overlong));
            assertFalse(coordinator.poisoned());
            assertEquals(1, lifecycle.trackedPlayers());
            assertEquals(0L, authority.issuer().recover(grant).lastSequence());

            DurablyIssuedServerAuthorityObservation issued = coordinator.issue(
                    PLAYER, request(grant, backendKeys, 1L, Duration.ofSeconds(4)))
                    .orElseThrow();
            assertEquals(1L, issued.observationSequence());
            assertEquals(1L, authority.issuer().recover(grant).lastSequence());
        }
    }

    @Test
    void disabledLifecycleAndProductionPluginRemainUnwired() throws Exception {
        KeyPair backendKeys = Ed25519Keys.generate(new SecureRandom());
        BackendAuthorityGrantCodec.VerifiedGrant grant = grant(Duration.ofSeconds(20));
        try (TestAuthority authority = TestAuthority.create(
                directory.resolve("disabled.log"), backendKeys)) {
            PaperServerAuthorityLifecycle lifecycle = PaperServerAuthorityLifecycle.disabled(
                    Clock.fixed(NOW, ZoneOffset.UTC));
            PaperServerAuthorityIssueCoordinator coordinator =
                    new PaperServerAuthorityIssueCoordinator(lifecycle, authority.issuer());
            assertTrue(coordinator.issue(PLAYER,
                    request(grant, backendKeys, 1L, Duration.ofSeconds(5))).isEmpty());
            assertEquals(0L, authority.issuer().recover(grant).lastSequence());
            assertFalse(coordinator.poisoned());
        }

        String plugin = Files.readString(paperProjectFile(
                "src/main/java/com/ellan/mcace/paper/MCAcePaperPlugin.java"));
        String config = Files.readString(paperProjectFile("src/main/resources/config.yml"));
        assertFalse(plugin.contains("PaperServerAuthorityIssueCoordinator"));
        assertFalse(plugin.contains("BACKEND_AUTHORITY_CHANNEL"));
        assertFalse(config.contains("server-authority:"));
    }

    private static ServerAuthorityObservationCodec.ObservationRequest request(
            BackendAuthorityGrantCodec.VerifiedGrant grant,
            KeyPair backendKeys,
            long observationSequence,
            Duration lifetime) {
        return request(grant, backendKeys, observationSequence, lifetime,
                grant.backendInstanceId(), grant.playerId(), grant.authenticatedSessionId(),
                grant.grantId(), grant.commitmentSha256(), grant.physicalLoginBinding(),
                grant.admissionTransportSequence(), NOW);
    }

    private static ServerAuthorityObservationCodec.ObservationRequest request(
            BackendAuthorityGrantCodec.VerifiedGrant grant,
            KeyPair backendKeys,
            long observationSequence,
            Duration lifetime,
            String backendInstanceId,
            UUID playerId,
            String authenticatedSessionId,
            UUID grantId,
            String grantCommitment,
            byte[] physicalBinding,
            long admissionSequence,
            Instant observedAt) {
        return new ServerAuthorityObservationCodec.ObservationRequest(
                backendInstanceId, BackendAuthorityPin.keyIdFor(backendKeys.getPublic()),
                playerId, authenticatedSessionId, grantId, grantCommitment, physicalBinding,
                admissionSequence, observationSequence, observedAt, lifetime, PROFILE,
                List.of(provider("domain-one", "provider-one", observedAt),
                        provider("domain-two", "provider-two", observedAt)));
    }

    private static ServerAuthorityObservationCodec.ProviderInput provider(
            String domain, String id, Instant observedAt) {
        return new ServerAuthorityObservationCodec.ProviderInput(
                domain, id, "1.0.0", "stable-family", 1, 1,
                observedAt, observedAt);
    }

    private static BackendAuthorityGrantCodec.VerifiedGrant grant(Duration lifetime)
            throws Exception {
        KeyPair proxy = Ed25519Keys.generate(new SecureRandom());
        byte[] binding = filledBinding((byte) 7);
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        BackendAuthorityGrantCodec codec =
                new BackendAuthorityGrantCodec(clock, new SecureRandom());
        BackendAuthorityGrantCodec.IssuedGrant issued = codec.issue(
                new BackendAuthorityGrantCodec.GrantRequest(
                        "proxy-1", "paper-1", PLAYER, SESSION, binding,
                        41L, 1L, lifetime), proxy.getPrivate());
        return codec.verify(
                issued.frame(), "proxy-1", "paper-1", PLAYER, SESSION,
                binding, 41L, 0L, proxy.getPublic(),
                new NonceReplayGuard(clock, Duration.ofMinutes(1)));
    }

    private static byte[] filledBinding(byte value) {
        byte[] binding = new byte[32];
        Arrays.fill(binding, value);
        return binding;
    }

    private static Path paperProjectFile(String relative) {
        Path direct = Path.of(relative);
        if (Files.isRegularFile(direct)) {
            return direct;
        }
        return Path.of("mcace-server-paper").resolve(relative);
    }

    private record TestAuthority(DurableServerAuthorityIssuer issuer)
            implements AutoCloseable {
        static TestAuthority create(Path path, KeyPair backendKeys) throws Exception {
            Files.write(path, ServerAuthorityJournalPreflight.requiredInitialContentUtf8(),
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            return new TestAuthority(new DurableServerAuthorityIssuer(
                    new ServerAuthorityObservationCodec(
                            Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom()),
                    backendKeys, path, 8192L));
        }

        @Override
        public void close() throws IOException {
            issuer.close();
        }
    }
}
