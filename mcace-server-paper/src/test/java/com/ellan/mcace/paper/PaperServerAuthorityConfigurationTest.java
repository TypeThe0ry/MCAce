package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.core.authority.BackendAuthorityPin;
import com.ellan.mcace.core.authority.BackendAuthorityProfile;
import com.ellan.mcace.core.authority.ServerAuthorityJournalPreflight;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Assumptions;
import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class PaperServerAuthorityConfigurationTest {
    @TempDir Path temporaryDirectory;

    @BeforeEach
    void useDedicatedPrivateAuthorityDirectory() throws Exception {
        temporaryDirectory = PaperAuthorityTestFiles.privateDirectory(
                temporaryDirectory, "private-paper-authority-root");
    }

    @Test
    void missingOrDisabledConfigurationLeavesRuntimeInert() throws Exception {
        assertNull(PaperServerAuthorityConfiguration.load(
                yaml("unrelated: true\n"), temporaryDirectory));
        assertNull(PaperServerAuthorityConfiguration.load(
                yaml("authority:\n  enabled: false\n  mode: MONITOR\n"), temporaryDirectory));
    }

    @Test
    void exactMonitorConfigurationLoadsReviewedKeysProfileAndJournal() throws Exception {
        KeyPair backend = createAuthorityFiles();
        BackendAuthorityProfile profile = profile();
        PaperServerAuthorityConfiguration configuration =
                PaperServerAuthorityConfiguration.load(
                        yaml(enabledYaml(backend, profile)), temporaryDirectory);

        assertNotNull(configuration);
        assertEquals("proxy-sg-1", configuration.proxyInstanceId());
        assertEquals("paper-sg-1", configuration.backendInstanceId());
        assertEquals(BackendAuthorityPin.keyIdFor(backend.getPublic()),
                configuration.backendKeyIdSha256());
        assertEquals(profile.sha256(), configuration.profile().sha256());
        assertEquals(temporaryDirectory.resolve("authority/issuance.log").toAbsolutePath(),
                configuration.issuanceJournal());
    }

    @Test
    void wrongModeUnknownKeyDigestOrEscapingPathFailsClosed() throws Exception {
        KeyPair backend = createAuthorityFiles();
        String exact = enabledYaml(backend, profile());

        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                yaml(exact.replace("mode: MONITOR", "mode: LIMIT")), temporaryDirectory));
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                yaml(exact.replace("  mode: MONITOR", "  mode: MONITOR\n  unreviewed: true")),
                temporaryDirectory));
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                yaml(exact.replace(profile().sha256(), "ab".repeat(32))), temporaryDirectory));
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                yaml(exact.replace(
                        "backend-public-key-path: authority/backend-public-key.txt",
                        "backend-public-key-path: ../outside.txt")), temporaryDirectory));
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                yaml(exact.replace("proxy-instance-id: proxy-sg-1", "proxy-instance-id: 123")),
                temporaryDirectory));
    }

    @Test
    void mismatchedKeyPairAndKeyFingerprintFailClosed() throws Exception {
        KeyPair backend = createAuthorityFiles();
        KeyPair other = Ed25519Keys.generate(new SecureRandom());
        Files.writeString(temporaryDirectory.resolve("authority/backend-public-key.txt"),
                Base64.getEncoder().encodeToString(other.getPublic().getEncoded()),
                StandardCharsets.US_ASCII);
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                yaml(enabledYaml(backend, profile())), temporaryDirectory));

        Files.writeString(temporaryDirectory.resolve("authority/backend-public-key.txt"),
                Base64.getEncoder().encodeToString(backend.getPublic().getEncoded()),
                StandardCharsets.US_ASCII);
        String staleFingerprint = enabledYaml(backend, profile()).replace(
                BackendAuthorityPin.keyIdFor(backend.getPublic()), "cd".repeat(32));
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                yaml(staleFingerprint), temporaryDirectory));
    }

    @Test
    void oversizedPrivateAndPublicKeysFailClosedBeforeDecode() throws Exception {
        KeyPair backend = createAuthorityFiles();
        YamlConfiguration configuration = yaml(enabledYaml(backend, profile()));
        Path privateKey = temporaryDirectory.resolve("authority/backend-private-key.pk8");
        Path publicKey = temporaryDirectory.resolve("authority/backend-public-key.txt");

        Files.write(privateKey, new byte[4097]);
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                configuration, temporaryDirectory));

        Files.write(privateKey, backend.getPrivate().getEncoded());
        Files.write(publicKey, new byte[4097]);
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                configuration, temporaryDirectory));
    }

    @Test
    void linkedKeyAndJournalFilesFailClosed() throws Exception {
        KeyPair backend = createAuthorityFiles();
        YamlConfiguration configuration = yaml(enabledYaml(backend, profile()));
        Path privateKey = temporaryDirectory.resolve("authority/backend-private-key.pk8");
        Path ordinaryPrivateKey = temporaryDirectory.resolve("ordinary-private-key.pk8");
        Files.copy(privateKey, ordinaryPrivateKey);
        Files.delete(privateKey);
        createSymbolicLinkOrSkip(privateKey, ordinaryPrivateKey);
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                configuration, temporaryDirectory));

        Files.delete(privateKey);
        PaperAuthorityTestFiles.writePrivate(
                privateKey, Files.readAllBytes(ordinaryPrivateKey));
        Path journal = temporaryDirectory.resolve("authority/issuance.log");
        Path ordinaryJournal = temporaryDirectory.resolve("ordinary-issuance.log");
        Files.copy(journal, ordinaryJournal);
        Files.delete(journal);
        Files.createSymbolicLink(journal, ordinaryJournal);
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                configuration, temporaryDirectory));
    }

    @Test
    void rawDuplicateAuthorityMappingsFailClosedBeforeBukkitCollapsedViewIsTrusted()
            throws Exception {
        KeyPair backend = createAuthorityFiles();
        String exact = enabledYaml(backend, profile());
        YamlConfiguration alreadyParsed = yaml(exact);
        List<String> duplicateRawConfigurations = List.of(
                exact.replace("  enabled: true", "  enabled: true\n  enabled: true"),
                exact.replace("  mode: MONITOR", "  mode: MONITOR\n  mode: MONITOR"),
                exact.replace(
                        "  backend-public-key-path: authority/backend-public-key.txt",
                        "  backend-public-key-path: authority/backend-public-key.txt\n"
                                + "  backend-public-key-path: authority/backend-public-key.txt"),
                exact.replace("        threshold: 2",
                        "        threshold: 2\n        threshold: 2"));

        Path rawConfiguration = temporaryDirectory.resolve("config.yml");
        for (String duplicate : duplicateRawConfigurations) {
            PaperAuthorityTestFiles.writePrivateString(
                    rawConfiguration, duplicate, StandardCharsets.UTF_8);
            assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                    alreadyParsed, temporaryDirectory));
        }
    }

    @Test
    void oversizedOrLinkedRawPaperConfigurationFailsClosed() throws Exception {
        KeyPair backend = createAuthorityFiles();
        String exact = enabledYaml(backend, profile());
        YamlConfiguration alreadyParsed = yaml(exact);
        Path rawConfiguration = temporaryDirectory.resolve("config.yml");
        PaperAuthorityTestFiles.writePrivate(
                rawConfiguration, new byte[(256 * 1024) + 1]);
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                alreadyParsed, temporaryDirectory));

        Path ordinaryConfiguration = temporaryDirectory.resolve("ordinary-config.yml");
        Files.writeString(ordinaryConfiguration, exact, StandardCharsets.UTF_8);
        Files.delete(rawConfiguration);
        createSymbolicLinkOrSkip(rawConfiguration, ordinaryConfiguration);
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                alreadyParsed, temporaryDirectory));
    }

    @Test
    void enabledAuthorityFilesAndRawConfigurationRequireOwnerOnlyPosixModes()
            throws Exception {
        Assumptions.assumeTrue(PaperAuthorityTestFiles.supportsPosix(temporaryDirectory));
        KeyPair backend = createAuthorityFiles();
        String exact = enabledYaml(backend, profile());
        YamlConfiguration parsed = yaml(exact);
        Path rawConfiguration = temporaryDirectory.resolve("config.yml");
        PaperAuthorityTestFiles.writePrivateString(
                rawConfiguration, exact, StandardCharsets.UTF_8);
        assertNotNull(PaperServerAuthorityConfiguration.load(parsed, temporaryDirectory));

        Files.setPosixFilePermissions(rawConfiguration, ownerReadWriteWithGroupRead());
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                parsed, temporaryDirectory));
        PaperAuthorityTestFiles.secureFile(rawConfiguration);

        Path privateKey = temporaryDirectory.resolve("authority/backend-private-key.pk8");
        Files.setPosixFilePermissions(privateKey, ownerReadWriteWithGroupRead());
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                parsed, temporaryDirectory));
        PaperAuthorityTestFiles.secureFile(privateKey);

        Path publicKey = temporaryDirectory.resolve("authority/backend-public-key.txt");
        Files.setPosixFilePermissions(publicKey, ownerReadWriteWithGroupRead());
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                parsed, temporaryDirectory));
        PaperAuthorityTestFiles.secureFile(publicKey);

        Path journal = temporaryDirectory.resolve("authority/issuance.log");
        Files.setPosixFilePermissions(journal, ownerReadWriteWithGroupRead());
        assertThrows(IOException.class, () -> PaperServerAuthorityConfiguration.load(
                parsed, temporaryDirectory));
    }

    private KeyPair createAuthorityFiles() throws Exception {
        Path authority = PaperAuthorityTestFiles.privateDirectory(
                temporaryDirectory, "authority");
        KeyPair backend = Ed25519Keys.generate(new SecureRandom());
        PaperAuthorityTestFiles.writePrivate(
                authority.resolve("backend-private-key.pk8"),
                backend.getPrivate().getEncoded());
        PaperAuthorityTestFiles.writePrivateString(
                authority.resolve("backend-public-key.txt"),
                Base64.getEncoder().encodeToString(backend.getPublic().getEncoded()),
                StandardCharsets.US_ASCII);
        PaperAuthorityTestFiles.writePrivate(
                authority.resolve("issuance.log"),
                ServerAuthorityJournalPreflight.requiredInitialContentUtf8());
        return backend;
    }

    private static Set<PosixFilePermission> ownerReadWriteWithGroupRead() {
        return Set.of(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.GROUP_READ);
    }

    private static BackendAuthorityProfile profile() {
        return new BackendAuthorityProfile(
                List.of(
                        new BackendAuthorityProfile.ProviderContract(
                                "grim-domain", "grim", "1.0.0", "movement-stable", 2),
                        new BackendAuthorityProfile.ProviderContract(
                                "vulcan-domain", "vulcan", "1.0.0", "movement-stable", 2)),
                2, Duration.ofSeconds(10), Duration.ofSeconds(30));
    }

    private static String enabledYaml(KeyPair backend, BackendAuthorityProfile profile) {
        return """
                authority:
                  enabled: true
                  mode: MONITOR
                  proxy-instance-id: proxy-sg-1
                  backend-instance-id: paper-sg-1
                  backend-private-key-path: authority/backend-private-key.pk8
                  backend-public-key-path: authority/backend-public-key.txt
                  backend-key-id-sha256: %s
                  issuance-journal-path: authority/issuance.log
                  journal-quota-bytes: 1048576
                  observation-ttl-ms: 10000
                  profile:
                    sha256: %s
                    required-independent-domains: 2
                    maximum-provider-window-ms: 10000
                    cooldown-ms: 30000
                    providers:
                      grim:
                        trust-domain-id: grim-domain
                        version: 1.0.0
                        stable-check-family: movement-stable
                        threshold: 2
                      vulcan:
                        trust-domain-id: vulcan-domain
                        version: 1.0.0
                        stable-check-family: movement-stable
                        threshold: 2
                """.formatted(BackendAuthorityPin.keyIdFor(backend.getPublic()), profile.sha256());
    }

    private static YamlConfiguration yaml(String text) throws Exception {
        YamlConfiguration configuration = new YamlConfiguration();
        configuration.loadFromString(text);
        return configuration;
    }

    private static void createSymbolicLinkOrSkip(Path link, Path target) {
        try {
            Files.createSymbolicLink(link, target);
        } catch (IOException | UnsupportedOperationException | SecurityException exception) {
            Assumptions.assumeTrue(false,
                    "symbolic links are unavailable in this test environment: " + exception);
        }
    }
}
