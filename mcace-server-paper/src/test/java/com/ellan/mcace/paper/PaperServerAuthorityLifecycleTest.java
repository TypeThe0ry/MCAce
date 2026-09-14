package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.authority.AuthorityProtocolException;
import com.ellan.mcace.core.authority.BackendAuthorityGrantCodec;
import com.ellan.mcace.core.authority.BackendAuthorityPin;
import com.ellan.mcace.core.authority.DurableServerAuthorityIssuer;
import com.ellan.mcace.core.authority.DurablyIssuedServerAuthorityObservation;
import com.ellan.mcace.core.authority.RecoveredServerAuthoritySequence;
import com.ellan.mcace.core.authority.ServerAuthorityJournalPreflight;
import com.ellan.mcace.core.authority.ServerAuthorityObservationCodec;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class PaperServerAuthorityLifecycleTest {
    private static final Instant NOW = Instant.parse("2026-08-13T00:00:00Z");
    private static final UUID PLAYER =
            UUID.fromString("00000000-0000-0000-0000-000000000001");

    @TempDir Path directory;

    @BeforeEach
    void useDedicatedPrivateAuthorityDirectory() throws Exception {
        directory = PaperAuthorityTestFiles.privateDirectory(
                directory, "private-paper-lifecycle-root");
    }

    @Test
    void disabledLifecycleRetainsNothingAndIssuesNothing() throws Exception {
        BackendAuthorityGrantCodec.VerifiedGrant verified =
                grant(1, 1, Duration.ofSeconds(20));
        try (TestAuthority authority = TestAuthority.create(
                directory.resolve("disabled.log"), Ed25519Keys.generate(new SecureRandom()))) {
            PaperServerAuthorityLifecycle lifecycle =
                    PaperServerAuthorityLifecycle.disabled(Clock.fixed(NOW, ZoneOffset.UTC));
            assertFalse(lifecycle.enabled());
            assertFalse(lifecycle.acceptVerifiedGrant(
                    PLAYER, verified, authority.issuer().recover(verified)));
            assertTrue(lifecycle.nextIssuance(PLAYER).isEmpty());
            assertEquals(0, lifecycle.trackedPlayers());
        }
    }

    @Test
    void onlyAnExactDurableTokenCommitsAndAbortReusesTheSequence() throws Exception {
        MutableClock clock = new MutableClock(NOW);
        BackendAuthorityGrantCodec.VerifiedGrant first =
                grant(1, 41, Duration.ofSeconds(20));
        BackendAuthorityGrantCodec.VerifiedGrant sameLifecycleOtherGrant =
                grant(2, 42, Duration.ofSeconds(20));
        BackendAuthorityGrantCodec.VerifiedGrant otherLifecycle = grantWithLifecycle(
                1, 41, Duration.ofSeconds(20), "other-session", filledBinding((byte) 8));
        KeyPair backendKeys = Ed25519Keys.generate(new SecureRandom());

        try (TestAuthority authority = TestAuthority.create(
                     directory.resolve("authority.log"), backendKeys);
             TestAuthority wrongIssuerAuthority = TestAuthority.create(
                     directory.resolve("wrong-issuer.log"),
                     Ed25519Keys.generate(new SecureRandom()));
             TestAuthority wrongGrantAuthority = TestAuthority.create(
                     directory.resolve("wrong-grant.log"), backendKeys);
             TestAuthority wrongLifecycleAuthority = TestAuthority.create(
                     directory.resolve("wrong-lifecycle.log"), backendKeys)) {
            PaperServerAuthorityLifecycle lifecycle =
                    PaperServerAuthorityLifecycle.enabledForTests(clock);
            RecoveredServerAuthoritySequence recovered = authority.issuer().recover(first);
            assertFalse(lifecycle.acceptVerifiedGrant(UUID.randomUUID(), first, recovered));
            assertTrue(lifecycle.acceptVerifiedGrant(PLAYER, first, recovered));

            PaperServerAuthorityLifecycle.IssuanceLease prepared =
                    lifecycle.nextIssuance(PLAYER).orElseThrow();
            assertEquals(1L, prepared.observationSequence());
            assertTrue(lifecycle.nextIssuance(PLAYER).isEmpty());

            DurablyIssuedServerAuthorityObservation wrongIssuerToken =
                    wrongIssuerAuthority.issue(first);
            assertFalse(lifecycle.commitIssuance(PLAYER, prepared, wrongIssuerToken));
            DurablyIssuedServerAuthorityObservation wrongGrantToken =
                    wrongGrantAuthority.issue(sameLifecycleOtherGrant);
            assertFalse(lifecycle.commitIssuance(PLAYER, prepared, wrongGrantToken));
            DurablyIssuedServerAuthorityObservation wrongLifecycleToken =
                    wrongLifecycleAuthority.issue(otherLifecycle);
            assertFalse(lifecycle.commitIssuance(PLAYER, prepared, wrongLifecycleToken));
            assertFalse(lifecycle.abortIssuance(UUID.randomUUID(), prepared));
            assertTrue(lifecycle.nextIssuance(PLAYER).isEmpty());

            assertTrue(lifecycle.abortIssuance(PLAYER, prepared));
            PaperServerAuthorityLifecycle.IssuanceLease retried =
                    lifecycle.nextIssuance(PLAYER).orElseThrow();
            assertEquals(1L, retried.observationSequence());
            assertFalse(prepared == retried);
            assertFalse(lifecycle.abortIssuance(PLAYER, prepared));
            DurablyIssuedServerAuthorityObservation firstToken = authority.issue(first);
            assertFalse(lifecycle.commitIssuance(UUID.randomUUID(), retried, firstToken));
            assertFalse(lifecycle.commitIssuance(PLAYER, prepared, firstToken));
            assertFalse(lifecycle.abortIssuance(PLAYER, prepared));
            assertTrue(lifecycle.commitIssuance(PLAYER, retried, firstToken));
            assertFalse(lifecycle.commitIssuance(PLAYER, retried, firstToken));

            PaperServerAuthorityLifecycle.IssuanceLease second =
                    lifecycle.nextIssuance(PLAYER).orElseThrow();
            assertEquals(2L, second.observationSequence());
            assertFalse(lifecycle.commitIssuance(PLAYER, second, firstToken));
            assertTrue(lifecycle.abortIssuance(PLAYER, second));

            RecoveredServerAuthoritySequence replacementRecovery =
                    authority.issuer().recover(sameLifecycleOtherGrant);
            assertEquals(1L, replacementRecovery.lastSequence());
            assertTrue(lifecycle.acceptVerifiedGrant(
                    PLAYER, sameLifecycleOtherGrant, replacementRecovery));
            PaperServerAuthorityLifecycle.IssuanceLease replacementLease =
                    lifecycle.nextIssuance(PLAYER).orElseThrow();
            assertEquals(2L, replacementLease.observationSequence());
            DurablyIssuedServerAuthorityObservation replacementToken =
                    authority.issue(sameLifecycleOtherGrant);
            assertTrue(lifecycle.commitIssuance(
                    PLAYER, replacementLease, replacementToken));

            assertFalse(lifecycle.acceptVerifiedGrant(PLAYER, sameLifecycleOtherGrant,
                    authority.issuer().recover(sameLifecycleOtherGrant)));
            BackendAuthorityGrantCodec.VerifiedGrant changedSession = grantWithLifecycle(
                    3, 43, Duration.ofSeconds(20),
                    "replacement-session", filledBinding((byte) 7));
            assertFalse(lifecycle.acceptVerifiedGrant(PLAYER, changedSession,
                    authority.issuer().recover(changedSession)));
            BackendAuthorityGrantCodec.VerifiedGrant changedBinding = grantWithLifecycle(
                    3, 43, Duration.ofSeconds(20),
                    "authenticated-session", filledBinding((byte) 8));
            assertFalse(lifecycle.acceptVerifiedGrant(PLAYER, changedBinding,
                    authority.issuer().recover(changedBinding)));

            lifecycle.remove(PLAYER);
            assertTrue(lifecycle.nextIssuance(PLAYER).isEmpty());
            assertEquals(0, lifecycle.trackedPlayers());

            BackendAuthorityGrantCodec.VerifiedGrant expiring =
                    grant(3, 43, Duration.ofSeconds(1));
            assertTrue(lifecycle.acceptVerifiedGrant(
                    PLAYER, expiring, authority.issuer().recover(expiring)));
            clock.advance(Duration.ofSeconds(1));
            lifecycle.expire();
            assertEquals(0, lifecycle.trackedPlayers());
            assertTrue(lifecycle.nextIssuance(PLAYER).isEmpty());
        }
    }

    @Test
    void rejectsDurableTokensOutsideTheExactGrantAndCommitTimeWindow() throws Exception {
        KeyPair backendKeys = Ed25519Keys.generate(new SecureRandom());

        BackendAuthorityGrantCodec.VerifiedGrant longGrant =
                grant(1, 41, Duration.ofSeconds(20));
        MutableClock expiredCommitClock = new MutableClock(NOW);
        try (TestAuthority authority = TestAuthority.create(
                directory.resolve("expired-token.log"), backendKeys,
                Clock.fixed(NOW, ZoneOffset.UTC))) {
            PaperServerAuthorityLifecycle lifecycle =
                    PaperServerAuthorityLifecycle.enabledForTests(expiredCommitClock);
            assertTrue(lifecycle.acceptVerifiedGrant(
                    PLAYER, longGrant, authority.issuer().recover(longGrant)));
            PaperServerAuthorityLifecycle.IssuanceLease lease =
                    lifecycle.nextIssuance(PLAYER).orElseThrow();
            DurablyIssuedServerAuthorityObservation expired =
                    authority.issue(longGrant, NOW, Duration.ofSeconds(1));
            expiredCommitClock.advance(Duration.ofSeconds(1));
            assertFalse(lifecycle.commitIssuance(PLAYER, lease, expired));
        }

        BackendAuthorityGrantCodec.VerifiedGrant shortGrant =
                grant(1, 41, Duration.ofSeconds(5));
        try (TestAuthority authority = TestAuthority.create(
                directory.resolve("over-grant-expiry.log"), backendKeys,
                Clock.fixed(NOW, ZoneOffset.UTC))) {
            PaperServerAuthorityLifecycle lifecycle =
                    PaperServerAuthorityLifecycle.enabledForTests(
                            Clock.fixed(NOW, ZoneOffset.UTC));
            assertTrue(lifecycle.acceptVerifiedGrant(
                    PLAYER, shortGrant, authority.issuer().recover(shortGrant)));
            PaperServerAuthorityLifecycle.IssuanceLease lease =
                    lifecycle.nextIssuance(PLAYER).orElseThrow();
            assertThrows(AuthorityProtocolException.class,
                    () -> authority.issue(shortGrant, NOW, Duration.ofSeconds(10)));
            assertEquals(0L, authority.issuer().recover(shortGrant).lastSequence());
            assertTrue(lifecycle.abortIssuance(PLAYER, lease));
        }

        try (TestAuthority authority = TestAuthority.create(
                directory.resolve("before-grant-issue.log"), backendKeys,
                Clock.fixed(NOW.minusSeconds(1), ZoneOffset.UTC))) {
            PaperServerAuthorityLifecycle lifecycle =
                    PaperServerAuthorityLifecycle.enabledForTests(
                            Clock.fixed(NOW, ZoneOffset.UTC));
            assertTrue(lifecycle.acceptVerifiedGrant(
                    PLAYER, longGrant, authority.issuer().recover(longGrant)));
            PaperServerAuthorityLifecycle.IssuanceLease lease =
                    lifecycle.nextIssuance(PLAYER).orElseThrow();
            assertThrows(AuthorityProtocolException.class, () -> authority.issue(
                    longGrant, NOW.minusSeconds(1), Duration.ofSeconds(5)));
            assertEquals(0L, authority.issuer().recover(longGrant).lastSequence());
            assertTrue(lifecycle.abortIssuance(PLAYER, lease));
        }

        try (TestAuthority authority = TestAuthority.create(
                directory.resolve("future-token.log"), backendKeys,
                Clock.fixed(NOW.plusSeconds(1), ZoneOffset.UTC))) {
            PaperServerAuthorityLifecycle lifecycle =
                    PaperServerAuthorityLifecycle.enabledForTests(
                            Clock.fixed(NOW, ZoneOffset.UTC));
            assertTrue(lifecycle.acceptVerifiedGrant(
                    PLAYER, longGrant, authority.issuer().recover(longGrant)));
            PaperServerAuthorityLifecycle.IssuanceLease lease =
                    lifecycle.nextIssuance(PLAYER).orElseThrow();
            DurablyIssuedServerAuthorityObservation future = authority.issue(
                    longGrant, NOW.plusSeconds(1), Duration.ofSeconds(5));
            assertTrue(future.matches(longGrant));
            assertFalse(lifecycle.commitIssuance(PLAYER, lease, future));
        }
    }

    @Test
    void restartSeedsPaperFromIssuerRecoveryWithoutProviderInput() throws Exception {
        Path path = directory.resolve("restart.log");
        KeyPair backendKeys = Ed25519Keys.generate(new SecureRandom());
        BackendAuthorityGrantCodec.VerifiedGrant verified =
                grant(1, 41, Duration.ofSeconds(20));
        AuthorityJournalTestSupport.initialize(path);

        try (TestAuthority first = TestAuthority.open(path, backendKeys)) {
            PaperServerAuthorityLifecycle lifecycle = PaperServerAuthorityLifecycle.enabledForTests(
                    Clock.fixed(NOW, ZoneOffset.UTC));
            assertTrue(lifecycle.acceptVerifiedGrant(
                    PLAYER, verified, first.issuer().recover(verified)));
            PaperServerAuthorityLifecycle.IssuanceLease lease =
                    lifecycle.nextIssuance(PLAYER).orElseThrow();
            DurablyIssuedServerAuthorityObservation token = first.issue(verified);
            assertEquals(1L, lease.observationSequence());
            assertTrue(lifecycle.commitIssuance(PLAYER, lease, token));
        }

        try (TestAuthority restarted = TestAuthority.open(path, backendKeys)) {
            PaperServerAuthorityLifecycle lifecycle = PaperServerAuthorityLifecycle.enabledForTests(
                    Clock.fixed(NOW, ZoneOffset.UTC));
            RecoveredServerAuthoritySequence recovered = restarted.issuer().recover(verified);
            assertEquals(1L, recovered.lastSequence());
            assertTrue(lifecycle.acceptVerifiedGrant(PLAYER, verified, recovered));
            PaperServerAuthorityLifecycle.IssuanceLease second =
                    lifecycle.nextIssuance(PLAYER).orElseThrow();
            assertEquals(2L, second.observationSequence());
            assertTrue(lifecycle.abortIssuance(PLAYER, second));
            assertEquals(2L,
                    lifecycle.nextIssuance(PLAYER).orElseThrow().observationSequence());
        }
    }

    @Test
    void productionPluginRegistersAuthorityChannelOnlyBehindDisabledMonitorConfiguration()
            throws Exception {
        String plugin = Files.readString(paperProjectFile(
                "src/main/java/com/ellan/mcace/paper/MCAcePaperPlugin.java"));
        String config = Files.readString(paperProjectFile("src/main/resources/config.yml"));
        assertTrue(plugin.contains("PaperServerAuthorityConfiguration.load("));
        assertTrue(plugin.contains("BACKEND_AUTHORITY_CHANNEL"));
        assertFalse(plugin.contains("PaperServerAuthorityLifecycle.enabledForTests("));
        assertTrue(config.contains("authority:"));
        assertTrue(config.contains("enabled: false"));
        assertTrue(config.contains("mode: MONITOR"));
    }

    private static Path paperProjectFile(String relative) {
        Path direct = Path.of(relative);
        if (Files.isRegularFile(direct)) {
            return direct;
        }
        return Path.of("mcace-server-paper").resolve(relative);
    }

    private static BackendAuthorityGrantCodec.VerifiedGrant grant(
            long grantSequence,
            long admissionSequence,
            Duration lifetime) throws Exception {
        return grantWithLifecycle(grantSequence, admissionSequence, lifetime,
                "authenticated-session", filledBinding((byte) 7));
    }

    private static BackendAuthorityGrantCodec.VerifiedGrant grantWithLifecycle(
            long grantSequence,
            long admissionSequence,
            Duration lifetime,
            String sessionId,
            byte[] binding) throws Exception {
        KeyPair proxy = Ed25519Keys.generate(new SecureRandom());
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        BackendAuthorityGrantCodec codec =
                new BackendAuthorityGrantCodec(clock, new SecureRandom());
        BackendAuthorityGrantCodec.IssuedGrant issued = codec.issue(
                new BackendAuthorityGrantCodec.GrantRequest(
                        "proxy-1", "paper-1", PLAYER, sessionId, binding,
                        admissionSequence, grantSequence, lifetime), proxy.getPrivate());
        return codec.verify(
                issued.frame(), "proxy-1", "paper-1", PLAYER, sessionId,
                binding, admissionSequence, grantSequence - 1, proxy.getPublic(),
                new NonceReplayGuard(clock, Duration.ofMinutes(1)));
    }

    private static byte[] filledBinding(byte value) {
        byte[] binding = new byte[32];
        java.util.Arrays.fill(binding, value);
        return binding;
    }

    private record TestAuthority(
            KeyPair backendKeys,
            DurableServerAuthorityIssuer issuer) implements AutoCloseable {
        static TestAuthority create(Path path, KeyPair backendKeys) throws Exception {
            return create(path, backendKeys, Clock.fixed(NOW, ZoneOffset.UTC));
        }

        static TestAuthority create(
                Path path, KeyPair backendKeys, Clock issuerClock) throws Exception {
            AuthorityJournalTestSupport.initialize(path);
            return open(path, backendKeys, issuerClock);
        }

        static TestAuthority open(Path path, KeyPair backendKeys) throws Exception {
            return open(path, backendKeys, Clock.fixed(NOW, ZoneOffset.UTC));
        }

        static TestAuthority open(
                Path path, KeyPair backendKeys, Clock issuerClock) throws Exception {
            return new TestAuthority(backendKeys, new DurableServerAuthorityIssuer(
                    new ServerAuthorityObservationCodec(
                            issuerClock, new SecureRandom()),
                    backendKeys, path, 8192));
        }

        DurablyIssuedServerAuthorityObservation issue(
                BackendAuthorityGrantCodec.VerifiedGrant grant) throws Exception {
            return issue(grant, NOW, Duration.ofSeconds(10));
        }

        DurablyIssuedServerAuthorityObservation issue(
                BackendAuthorityGrantCodec.VerifiedGrant grant,
                Instant observedAt,
                Duration lifetime) throws Exception {
            long sequence = Math.incrementExact(issuer.recover(grant).lastSequence());
            ServerAuthorityObservationCodec.ObservationRequest request =
                    new ServerAuthorityObservationCodec.ObservationRequest(
                    grant.backendInstanceId(), BackendAuthorityPin.keyIdFor(backendKeys.getPublic()),
                    grant.playerId(), grant.authenticatedSessionId(), grant.grantId(),
                    grant.commitmentSha256(), grant.physicalLoginBinding(),
                    grant.admissionTransportSequence(), sequence, observedAt, lifetime,
                    "ab".repeat(32), List.of(
                    provider("domain-one", "provider-one", observedAt),
                    provider("domain-two", "provider-two", observedAt)));
            return issuer.issue(grant, sequence, request);
        }

        private static ServerAuthorityObservationCodec.ProviderInput provider(
                String domain, String id, Instant observedAt) {
            return new ServerAuthorityObservationCodec.ProviderInput(
                    domain, id, "1.0.0", "stable-family", 1, 1,
                    observedAt, observedAt);
        }

        @Override
        public void close() throws IOException {
            issuer.close();
        }
    }

    private static final class AuthorityJournalTestSupport {
        private AuthorityJournalTestSupport() {
        }

        static void initialize(Path path) throws Exception {
            PaperAuthorityTestFiles.initializeJournal(path);
            assertEquals(ServerAuthorityJournalPreflight.requiredHeaderLine() + "\n",
                    Files.readString(path, StandardCharsets.UTF_8));
        }
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return instant; }
    }
}
