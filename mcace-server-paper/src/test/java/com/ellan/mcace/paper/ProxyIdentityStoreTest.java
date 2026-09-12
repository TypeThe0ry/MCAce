package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.core.authority.AuthorityFilePreflight;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class ProxyIdentityStoreTest {
    @TempDir Path temporaryDirectory;

    @Test
    void loadsPinnedEd25519PublicKey() throws Exception {
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        Path root = AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                temporaryDirectory.resolve("paper-data"), "Paper proxy-pin directory");
        Path pin = root.resolve("proxy-public-key.txt");
        AuthorityFilePreflight.writePrivateFileAtomically(
                root, pin, Base64.getEncoder().encode(identity.getPublic().getEncoded()),
                "Paper proxy public-key pin");

        assertArrayEquals(identity.getPublic().getEncoded(), ProxyIdentityStore.load(pin).getEncoded());
    }

    @Test
    void failsClosedForMissingOrMalformedPin() throws Exception {
        Path missing = temporaryDirectory.resolve("missing").resolve("velocity-public-key.txt");
        assertThrows(IOException.class, () -> ProxyIdentityStore.load(missing));

        Path root = AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                temporaryDirectory.resolve("malformed-paper-data"),
                "malformed Paper proxy-pin directory");
        Path malformed = root.resolve("proxy-public-key.txt");
        AuthorityFilePreflight.writePrivateFileAtomically(
                root, malformed, "not-base64".getBytes(StandardCharsets.US_ASCII),
                "malformed Paper proxy public-key pin");
        assertThrows(IOException.class, () -> ProxyIdentityStore.load(malformed));
    }

    @Test
    void rejectsOversizedAndLinkedPins() throws Exception {
        Path root = AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                temporaryDirectory.resolve("negative-paper-data"),
                "negative Paper proxy-pin directory");
        Path oversized = root.resolve("oversized-public-key.txt");
        AuthorityFilePreflight.writePrivateFileAtomically(
                root, oversized, new byte[4097], "oversized Paper proxy public-key pin");
        assertThrows(IOException.class, () -> ProxyIdentityStore.load(oversized));

        Path outsideRoot = AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                temporaryDirectory.resolve("outside-paper-data"),
                "outside Paper proxy-pin directory");
        Path outside = outsideRoot.resolve("proxy-public-key.txt");
        AuthorityFilePreflight.writePrivateFileAtomically(
                outsideRoot, outside, "not-a-pin".getBytes(StandardCharsets.US_ASCII),
                "outside Paper proxy public-key pin");
        Path linked = root.resolve("linked-public-key.txt");
        try {
            Files.createSymbolicLink(linked, outside);
        } catch (IOException | UnsupportedOperationException | SecurityException exception) {
            org.junit.jupiter.api.Assumptions.assumeTrue(false,
                    "symbolic links are unavailable in this test environment: " + exception);
        }
        assertThrows(IOException.class, () -> ProxyIdentityStore.load(linked));
    }

    @Test
    void acceptsPosixCopiedPublicPinButRejectsGroupWritablePin() throws Exception {
        Assumptions.assumeTrue(Files.getFileStore(temporaryDirectory)
                .supportsFileAttributeView("posix"));
        Path root = Files.createDirectory(temporaryDirectory.resolve("copied-paper-data"));
        Files.setPosixFilePermissions(root, Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE,
                java.nio.file.attribute.PosixFilePermission.GROUP_READ,
                java.nio.file.attribute.PosixFilePermission.GROUP_EXECUTE,
                java.nio.file.attribute.PosixFilePermission.OTHERS_READ,
                java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE));
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        Path pin = root.resolve("proxy-public-key.txt");
        Files.write(pin, Base64.getEncoder().encode(identity.getPublic().getEncoded()));
        Files.setPosixFilePermissions(pin, Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                java.nio.file.attribute.PosixFilePermission.GROUP_READ,
                java.nio.file.attribute.PosixFilePermission.OTHERS_READ));

        assertArrayEquals(identity.getPublic().getEncoded(),
                ProxyIdentityStore.load(pin).getEncoded());

        Files.setPosixFilePermissions(pin, Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                java.nio.file.attribute.PosixFilePermission.GROUP_READ,
                java.nio.file.attribute.PosixFilePermission.GROUP_WRITE));
        assertThrows(IOException.class, () -> ProxyIdentityStore.load(pin));
    }
}
