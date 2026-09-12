package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.authority.AuthorityFilePreflight;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.policy.PolicyException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class DelegatedPolicyKeyStoreTest {
    @TempDir Path temporaryDirectory;

    @Test
    void missingStoreIsEmptyAndRotationPersistsMatchingPrivatePair() throws Exception {
        Path root = temporaryDirectory.resolve("delegated-key");
        assertTrue(DelegatedPolicyKeyStore.load(root).isEmpty());

        KeyPair first = DelegatedPolicyKeyStore.rotate(root, new SecureRandom());
        KeyPair firstLoaded = DelegatedPolicyKeyStore.load(root).orElseThrow();
        assertArrayEquals(first.getPublic().getEncoded(), firstLoaded.getPublic().getEncoded());

        KeyPair second = DelegatedPolicyKeyStore.rotate(root, new SecureRandom());
        KeyPair secondLoaded = DelegatedPolicyKeyStore.load(root).orElseThrow();
        assertArrayEquals(second.getPublic().getEncoded(), secondLoaded.getPublic().getEncoded());
        AuthorityFilePreflight.requirePrivateRegularFile(
                root, root.resolve("delegated-private-key.pk8"),
                "test delegated private key");
        AuthorityFilePreflight.requirePrivateRegularFile(
                root, root.resolve("delegated-public-key.x509"),
                "test delegated public key");
        try (Stream<Path> entries = Files.list(root)) {
            assertTrue(entries.noneMatch(
                    path -> path.getFileName().toString().endsWith(".tmp")));
        }
    }

    @Test
    void incompleteOversizedMismatchedAndLinkedStoresFailClosed() throws Exception {
        Path root = privateRoot("negative-delegated-key");
        KeyPair first = Ed25519Keys.generate(new SecureRandom());
        Path privateKey = root.resolve("delegated-private-key.pk8");
        Path publicKey = root.resolve("delegated-public-key.x509");
        AuthorityFilePreflight.writePrivateFileAtomically(
                root, privateKey, first.getPrivate().getEncoded(),
                "test delegated private key");
        assertThrows(PolicyException.class, () -> DelegatedPolicyKeyStore.load(root));

        AuthorityFilePreflight.writePrivateFileAtomically(
                root, publicKey, first.getPublic().getEncoded(),
                "test delegated public key");
        AuthorityFilePreflight.replacePrivateFileAtomically(
                root, privateKey, new byte[4097], "oversized delegated private key");
        assertThrows(PolicyException.class, () -> DelegatedPolicyKeyStore.load(root));

        KeyPair second = Ed25519Keys.generate(new SecureRandom());
        AuthorityFilePreflight.replacePrivateFileAtomically(
                root, privateKey, first.getPrivate().getEncoded(),
                "test delegated private key");
        AuthorityFilePreflight.replacePrivateFileAtomically(
                root, publicKey, second.getPublic().getEncoded(),
                "mismatched delegated public key");
        assertThrows(PolicyException.class, () -> DelegatedPolicyKeyStore.load(root));

        Path outsideRoot = privateRoot("outside-delegated-key");
        Path outside = outsideRoot.resolve("outside-private-key.pk8");
        AuthorityFilePreflight.writePrivateFileAtomically(
                outsideRoot, outside, first.getPrivate().getEncoded(),
                "outside delegated private key");
        Files.delete(privateKey);
        createSymbolicLinkOrSkip(privateKey, outside);
        assertThrows(PolicyException.class, () -> DelegatedPolicyKeyStore.load(root));
    }

    @Test
    void insecureLegacyDirectoryRequiresExplicitMigrationOnPosix() throws Exception {
        Assumptions.assumeTrue(Files.getFileStore(temporaryDirectory)
                .supportsFileAttributeView("posix"));
        Path root = Files.createDirectory(temporaryDirectory.resolve("legacy-delegated-key"));
        Files.setPosixFilePermissions(root, Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE,
                java.nio.file.attribute.PosixFilePermission.GROUP_READ,
                java.nio.file.attribute.PosixFilePermission.GROUP_EXECUTE,
                java.nio.file.attribute.PosixFilePermission.OTHERS_READ,
                java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE));

        assertThrows(PolicyException.class, () -> DelegatedPolicyKeyStore.load(root));
        assertThrows(PolicyException.class,
                () -> DelegatedPolicyKeyStore.rotate(root, new SecureRandom()));
    }

    @Test
    void concurrentRotationsAreSerializedAndLeaveOneLoadablePair() throws Exception {
        Path root = temporaryDirectory.resolve("concurrent-delegated-key");
        try (var executor = Executors.newFixedThreadPool(2)) {
            List<Callable<KeyPair>> tasks = List.of(
                    () -> DelegatedPolicyKeyStore.rotate(root, new SecureRandom()),
                    () -> DelegatedPolicyKeyStore.rotate(root, new SecureRandom()));
            List<KeyPair> returned = executor.invokeAll(tasks).stream()
                    .map(future -> {
                        try {
                            return future.get();
                        } catch (Exception exception) {
                            throw new AssertionError(exception);
                        }
                    })
                    .toList();
            KeyPair loaded = DelegatedPolicyKeyStore.load(root).orElseThrow();
            assertTrue(returned.stream().anyMatch(pair -> java.util.Arrays.equals(
                    pair.getPublic().getEncoded(), loaded.getPublic().getEncoded())));
        }
    }

    private Path privateRoot(String name) throws IOException {
        return AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                temporaryDirectory.resolve(name), "test delegated policy key directory");
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
