package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.core.authority.AuthorityFilePreflight;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Set;
import org.bukkit.configuration.file.YamlConfiguration;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class PaperIntegrationConfigurationTest {
    @TempDir Path temporaryDirectory;

    @Test
    void loadsBoundedPrivateKeyFromRelativeOwnerControlledPath() throws Exception {
        Path root = privateRoot("valid-paper-data");
        Path credentials = AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                root.resolve("credentials"), "Paper cloud test credentials");
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        Path privateKey = credentials.resolve("server-private-key.pk8");
        AuthorityFilePreflight.writePrivateFileAtomically(
                credentials, privateKey, identity.getPrivate().getEncoded(),
                "Paper cloud test private key");

        PaperIntegrationConfiguration loaded = PaperIntegrationConfiguration.load(
                cloudConfiguration("credentials/server-private-key.pk8"), root);

        assertNotNull(loaded.cloud());
        assertArrayEquals(identity.getPrivate().getEncoded(),
                loaded.cloud().privateKey().getEncoded());
    }

    @Test
    void absoluteAndEscapingCloudPrivateKeyPathsFailClosed() throws Exception {
        Path root = privateRoot("path-paper-data");

        assertThrows(IOException.class, () -> PaperIntegrationConfiguration.load(
                cloudConfiguration("../outside.pk8"), root));
        assertThrows(IOException.class, () -> PaperIntegrationConfiguration.load(
                cloudConfiguration(temporaryDirectory.resolve("outside.pk8")
                        .toAbsolutePath().toString()), root));
    }

    @Test
    void oversizedOrLinkedCloudPrivateKeyFailsClosed() throws Exception {
        Path root = privateRoot("negative-paper-data");
        Path privateKey = root.resolve("cloud-server-private-key.pk8");
        AuthorityFilePreflight.writePrivateFileAtomically(
                root, privateKey, new byte[4097], "oversized Paper cloud private key");
        assertThrows(IOException.class, () -> PaperIntegrationConfiguration.load(
                cloudConfiguration("cloud-server-private-key.pk8"), root));

        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        Path outsideRoot = privateRoot("outside-paper-data");
        Path outside = outsideRoot.resolve("outside-private-key.pk8");
        AuthorityFilePreflight.writePrivateFileAtomically(
                outsideRoot, outside, identity.getPrivate().getEncoded(),
                "outside Paper cloud private key");
        Files.delete(privateKey);
        createSymbolicLinkOrSkip(privateKey, outside);
        assertThrows(IOException.class, () -> PaperIntegrationConfiguration.load(
                cloudConfiguration("cloud-server-private-key.pk8"), root));
    }

    @Test
    void weakPrivateLeafOrWritableApplicationDirectoryFailsClosedOnPosix()
            throws Exception {
        Assumptions.assumeTrue(Files.getFileStore(temporaryDirectory)
                .supportsFileAttributeView("posix"));
        Path root = privateRoot("weak-mode-paper-data");
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        Path privateKey = root.resolve("cloud-server-private-key.pk8");
        AuthorityFilePreflight.writePrivateFileAtomically(
                root, privateKey, identity.getPrivate().getEncoded(),
                "weak-mode Paper cloud private key");
        YamlConfiguration configuration = cloudConfiguration("cloud-server-private-key.pk8");

        Files.setPosixFilePermissions(privateKey, Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                java.nio.file.attribute.PosixFilePermission.GROUP_READ));
        assertThrows(IOException.class,
                () -> PaperIntegrationConfiguration.load(configuration, root));

        Files.setPosixFilePermissions(privateKey, Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
        Files.setPosixFilePermissions(root, Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE,
                java.nio.file.attribute.PosixFilePermission.GROUP_WRITE));
        assertThrows(IOException.class,
                () -> PaperIntegrationConfiguration.load(configuration, root));
    }

    private Path privateRoot(String name) throws IOException {
        return AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                temporaryDirectory.resolve(name), "Paper cloud test data directory");
    }

    private static YamlConfiguration cloudConfiguration(String privateKeyPath) {
        YamlConfiguration configuration = new YamlConfiguration();
        configuration.set("cloud.enabled", true);
        configuration.set("cloud.endpoint", "https://mcace.example.invalid");
        configuration.set("cloud.server-id", "paper-test-1");
        configuration.set("cloud.private-key-path", privateKeyPath);
        configuration.set("cloud.queue-capacity", 16);
        configuration.set("cloud.request-timeout-ms", 1000L);
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
