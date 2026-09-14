package com.ellan.mcace.core.authority;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class ProxyServerAuthorityRuntimeTest {
    @TempDir Path temporaryDirectory;

    @BeforeEach
    void useDedicatedPrivateAuthorityDirectory() throws Exception {
        temporaryDirectory = AuthorityJournalTestFixture.privateDirectory(
                temporaryDirectory, "private-proxy-authority-root");
    }

    @Test
    void disabledDefaultCreatesNoAuthorityRegistry() throws Exception {
        ProxyServerAuthorityConfiguration configuration =
                ProxyServerAuthorityConfiguration.loadOrCreate(
                        temporaryDirectory.resolve(ProxyServerAuthorityConfiguration.FILE_NAME));
        assertFalse(configuration.enabled());
        assertFalse(configuration.registry().enabled());
        assertTrue(Files.readString(
                temporaryDirectory.resolve(ProxyServerAuthorityConfiguration.FILE_NAME))
                .contains("authority.enabled=false"));
    }

    @Test
    void exactConfigIssuesAndVerifiesMonitorOnlyObservation() throws Exception {
        KeyPair proxy = Ed25519Keys.generate(new SecureRandom());
        KeyPair backend = Ed25519Keys.generate(new SecureRandom());
        ProxyServerAuthorityConfiguration configuration = enabledConfiguration(backend);
        ProxyServerAuthorityRuntime runtime = new ProxyServerAuthorityRuntime(
                configuration, proxy, AuthorityTestFixtures.CLOCK, new SecureRandom());

        ProxyServerAuthorityRuntime.IssuedGrant grant = runtime.issueGrant(
                AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.ADMISSION_SEQUENCE);
        assertEquals(1L, grant.grantSequence());
        assertEquals(AuthorityTestFixtures.BACKEND_INSTANCE, grant.backendInstanceId());

        ServerAuthorityObservationCodec.ProviderInput grim = provider("grim-domain", "grim");
        ServerAuthorityObservationCodec.ProviderInput vulcan = provider("vulcan-domain", "vulcan");
        ServerAuthorityObservationCodec.ObservationRequest request =
                new ServerAuthorityObservationCodec.ObservationRequest(
                        grant.backendInstanceId(), BackendAuthorityPin.keyIdFor(backend.getPublic()),
                        grant.playerId(), grant.authenticatedSessionId(), grant.grantId(),
                        grant.grantCommitmentSha256(), grant.physicalLoginBinding(),
                        grant.admissionTransportSequence(), 1L, AuthorityTestFixtures.NOW,
                        Duration.ofSeconds(10), AuthorityTestFixtures.PROFILE,
                        List.of(grim, vulcan));
        byte[] signed = new ServerAuthorityObservationCodec(
                AuthorityTestFixtures.CLOCK, new SecureRandom())
                .sign(request, backend.getPrivate()).frame();

        VerifiedServerAuthorityObservation verified = runtime.acceptObservation(
                AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.ADMISSION_SEQUENCE,
                signed);
        assertEquals(1L, verified.observationSequence());
        assertEquals(AuthorityTestFixtures.PROFILE, verified.authorityProfileSha256());
        assertEquals(2, verified.providers().size());
        assertThrows(AuthorityProtocolException.class, () -> runtime.acceptObservation(
                AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION,
                AuthorityTestFixtures.ADMISSION_SEQUENCE,
                signed));
    }

    @Test
    void routineAdmissionRefreshRetainsOneGrantUntilItsBoundedExpiry() throws Exception {
        KeyPair proxy = Ed25519Keys.generate(new SecureRandom());
        KeyPair backend = Ed25519Keys.generate(new SecureRandom());
        MutableClock clock = new MutableClock(AuthorityTestFixtures.NOW);
        ProxyServerAuthorityRuntime runtime = new ProxyServerAuthorityRuntime(
                enabledConfiguration(backend), proxy, clock, new SecureRandom());

        ProxyServerAuthorityRuntime.IssuedGrant first = runtime.issueGrant(
                AuthorityTestFixtures.REGISTERED_BACKEND, AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, 41L);
        assertTrue(first.newlyIssued());

        clock.set(AuthorityTestFixtures.NOW.plusSeconds(5));
        ProxyServerAuthorityRuntime.IssuedGrant refresh = runtime.issueGrant(
                AuthorityTestFixtures.REGISTERED_BACKEND, AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, 42L);
        assertFalse(refresh.newlyIssued());
        assertEquals(first.grantId(), refresh.grantId());
        assertEquals(1L, refresh.grantSequence());
        assertEquals(41L, refresh.admissionTransportSequence(),
                "routine snapshot refresh must not rotate the authority binding");
        assertEquals(41L, runtime.currentGrant(AuthorityTestFixtures.PLAYER)
                .orElseThrow().admissionTransportSequence());
        assertThrows(AuthorityProtocolException.class, () -> runtime.issueGrant(
                AuthorityTestFixtures.REGISTERED_BACKEND, AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, 42L));

        clock.set(AuthorityTestFixtures.NOW.plusSeconds(20));
        ProxyServerAuthorityRuntime.IssuedGrant replacement = runtime.issueGrant(
                AuthorityTestFixtures.REGISTERED_BACKEND, AuthorityTestFixtures.PLAYER,
                AuthorityTestFixtures.SESSION, 43L);
        assertTrue(replacement.newlyIssued());
        assertEquals(2L, replacement.grantSequence());
        assertEquals(43L, replacement.admissionTransportSequence());
        assertNotEquals(first.grantId(), replacement.grantId());
    }

    @Test
    void enabledConfigRejectsUnknownKeyAndWrongActionCeiling() throws Exception {
        KeyPair backend = Ed25519Keys.generate(new SecureRandom());
        Path configurationPath = writeEnabledConfiguration(backend);
        Files.writeString(configurationPath,
                Files.readString(configurationPath) + "authority.unreviewed=true\n",
                StandardCharsets.UTF_8);
        assertThrows(java.io.IOException.class,
                () -> ProxyServerAuthorityConfiguration.loadOrCreate(configurationPath));

        writeEnabledConfiguration(backend);
        String content = Files.readString(configurationPath)
                .replace("authority.mode=MONITOR", "authority.mode=LIMIT");
        Files.writeString(configurationPath, content, StandardCharsets.UTF_8);
        assertThrows(java.io.IOException.class,
                () -> ProxyServerAuthorityConfiguration.loadOrCreate(configurationPath));
    }

    @Test
    void duplicateConfigurationKeyIsRejectedEvenWhenAuthorityWouldBeDisabled()
            throws Exception {
        Path configuration = temporaryDirectory.resolve(
                ProxyServerAuthorityConfiguration.FILE_NAME);
        AuthorityJournalTestFixture.writePrivateString(configuration, """
                authority.enabled=false
                authority.mode=MONITOR
                authority.mode=MONITOR
                """, StandardCharsets.UTF_8);
        assertThrows(java.io.IOException.class,
                () -> ProxyServerAuthorityConfiguration.loadOrCreate(configuration));
    }

    @Test
    void oversizedConfigurationAndPublicKeyFailClosedBeforeParsingOrDecoding()
            throws Exception {
        Path oversizedConfiguration = temporaryDirectory.resolve(
                ProxyServerAuthorityConfiguration.FILE_NAME);
        AuthorityJournalTestFixture.writePrivate(
                oversizedConfiguration, new byte[(64 * 1024) + 1]);
        assertThrows(java.io.IOException.class,
                () -> ProxyServerAuthorityConfiguration.loadOrCreate(oversizedConfiguration));

        KeyPair backend = Ed25519Keys.generate(new SecureRandom());
        Path configuration = writeEnabledConfiguration(backend);
        Files.write(temporaryDirectory.resolve("authority/paper-public-key.txt"),
                new byte[4097]);
        assertThrows(java.io.IOException.class,
                () -> ProxyServerAuthorityConfiguration.loadOrCreate(configuration));
    }

    @Test
    void linkedConfigurationAndPublicKeyFailClosed() throws Exception {
        KeyPair backend = Ed25519Keys.generate(new SecureRandom());
        Path configuration = writeEnabledConfiguration(backend);
        Path publicKey = temporaryDirectory.resolve("authority/paper-public-key.txt");
        Path ordinaryKey = temporaryDirectory.resolve("ordinary-public-key.txt");
        Files.copy(publicKey, ordinaryKey);
        Files.delete(publicKey);
        createSymbolicLinkOrSkip(publicKey, ordinaryKey);
        assertThrows(java.io.IOException.class,
                () -> ProxyServerAuthorityConfiguration.loadOrCreate(configuration));

        Files.delete(publicKey);
        AuthorityJournalTestFixture.writePrivate(publicKey, Files.readAllBytes(ordinaryKey));
        Path ordinaryConfiguration = temporaryDirectory.resolve("ordinary-authority.properties");
        Files.copy(configuration, ordinaryConfiguration);
        Files.delete(configuration);
        Files.createSymbolicLink(configuration, ordinaryConfiguration);
        assertThrows(java.io.IOException.class,
                () -> ProxyServerAuthorityConfiguration.loadOrCreate(configuration));
    }

    @Test
    void enabledConfigurationAndPublicKeyRequireOwnerOnlyPosixModes() throws Exception {
        Assumptions.assumeTrue(
                Files.getFileStore(temporaryDirectory).supportsFileAttributeView("posix"));
        KeyPair backend = Ed25519Keys.generate(new SecureRandom());
        Path configuration = writeEnabledConfiguration(backend);
        Files.setPosixFilePermissions(configuration, Set.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.GROUP_READ));
        assertThrows(java.io.IOException.class,
                () -> ProxyServerAuthorityConfiguration.loadOrCreate(configuration));

        AuthorityJournalTestFixture.secureFileIfPosix(configuration);
        Path publicKey = temporaryDirectory.resolve("authority/paper-public-key.txt");
        Files.setPosixFilePermissions(publicKey, Set.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OTHERS_READ));
        assertThrows(java.io.IOException.class,
                () -> ProxyServerAuthorityConfiguration.loadOrCreate(configuration));
    }

    private ProxyServerAuthorityConfiguration enabledConfiguration(KeyPair backend) throws Exception {
        return ProxyServerAuthorityConfiguration.loadOrCreate(writeEnabledConfiguration(backend));
    }

    private Path writeEnabledConfiguration(KeyPair backend) throws Exception {
        Path keys = AuthorityJournalTestFixture.privateDirectory(
                temporaryDirectory, "authority");
        AuthorityJournalTestFixture.writePrivateString(
                keys.resolve("paper-public-key.txt"),
                Base64.getEncoder().encodeToString(backend.getPublic().getEncoded()),
                StandardCharsets.US_ASCII);
        Path configuration = temporaryDirectory.resolve(ProxyServerAuthorityConfiguration.FILE_NAME);
        String profile = AuthorityTestFixtures.PROFILE;
        AuthorityJournalTestFixture.writePrivateString(configuration, """
                authority.enabled=true
                authority.mode=MONITOR
                authority.proxy-instance-id=proxy-sg-1
                authority.grant-ttl-ms=20000
                authority.backends=survival
                authority.backend.survival.instance-id=paper-sg-1
                authority.backend.survival.public-key-path=authority/paper-public-key.txt
                authority.backend.survival.key-id-sha256=%s
                authority.backend.survival.profiles=stable
                authority.backend.survival.profile.stable.sha256=%s
                authority.backend.survival.profile.stable.required-independent-domains=2
                authority.backend.survival.profile.stable.maximum-provider-window-ms=15000
                authority.backend.survival.profile.stable.cooldown-ms=30000
                authority.backend.survival.profile.stable.providers=grim,vulcan
                authority.backend.survival.profile.stable.provider.grim.trust-domain-id=grim-domain
                authority.backend.survival.profile.stable.provider.grim.version=1.0.0
                authority.backend.survival.profile.stable.provider.grim.stable-check-family=movement-stable
                authority.backend.survival.profile.stable.provider.grim.threshold=2
                authority.backend.survival.profile.stable.provider.vulcan.trust-domain-id=vulcan-domain
                authority.backend.survival.profile.stable.provider.vulcan.version=1.0.0
                authority.backend.survival.profile.stable.provider.vulcan.stable-check-family=movement-stable
                authority.backend.survival.profile.stable.provider.vulcan.threshold=2
                """.formatted(BackendAuthorityPin.keyIdFor(backend.getPublic()), profile),
                StandardCharsets.UTF_8);
        return configuration;
    }

    private static ServerAuthorityObservationCodec.ProviderInput provider(
            String domain, String providerId) {
        return new ServerAuthorityObservationCodec.ProviderInput(
                domain, providerId, "1.0.0", "movement-stable", 2, 2,
                AuthorityTestFixtures.NOW, AuthorityTestFixtures.NOW);
    }

    private static void createSymbolicLinkOrSkip(Path link, Path target) {
        try {
            Files.createSymbolicLink(link, target);
        } catch (java.io.IOException | UnsupportedOperationException | SecurityException exception) {
            Assumptions.assumeTrue(false,
                    "symbolic links are unavailable in this test environment: " + exception);
        }
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
