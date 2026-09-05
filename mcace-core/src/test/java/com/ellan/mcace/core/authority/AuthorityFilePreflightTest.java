package com.ellan.mcace.core.authority;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class AuthorityFilePreflightTest {
    @TempDir Path temporaryDirectory;

    @Test
    void boundedReadAcceptsOrdinaryFileAndRejectsOversizedOrNonRegularLeaf()
            throws Exception {
        Path root = temporaryDirectory.resolve("authority-root");
        AuthorityFilePreflight.createDirectoriesWithoutLinks(root.resolve("keys"));
        Path key = root.resolve("keys/public.txt");
        byte[] expected = "bounded-authority-key".getBytes(StandardCharsets.US_ASCII);
        Files.write(key, expected);

        assertArrayEquals(expected, AuthorityFilePreflight.readBoundedRegularFile(
                root, key, expected.length, "test authority key"));
        assertThrows(IOException.class,
                () -> AuthorityFilePreflight.readBoundedRegularFile(
                        root, key, expected.length - 1, "test authority key"));
        assertThrows(IOException.class,
                () -> AuthorityFilePreflight.readBoundedRegularFile(
                        root, root.resolve("keys"), 4096, "test authority key"));
    }

    @Test
    void lexicalEscapeAndAbsoluteConfiguredPathFailClosed() throws Exception {
        Path root = AuthorityFilePreflight.createDirectoriesWithoutLinks(
                temporaryDirectory.resolve("authority-root"));
        assertThrows(IOException.class, () -> AuthorityFilePreflight.resolveRelative(
                root, "../outside.txt", "test authority key path"));
        assertThrows(IOException.class, () -> AuthorityFilePreflight.resolveRelative(
                root, temporaryDirectory.resolve("outside.txt").toString(),
                "test authority key path"));
        assertThrows(IOException.class, () -> AuthorityFilePreflight.resolveRelative(
                root, ".", "test authority key path"));
    }

    @Test
    void linkedLeafAndLinkedAncestorFailClosed() throws Exception {
        Path root = AuthorityFilePreflight.createDirectoriesWithoutLinks(
                temporaryDirectory.resolve("authority-root"));
        Path outsideDirectory = Files.createDirectories(temporaryDirectory.resolve("outside"));
        Path outsideKey = outsideDirectory.resolve("public.txt");
        Files.writeString(outsideKey, "outside", StandardCharsets.US_ASCII);

        Path linkedLeaf = root.resolve("linked-public.txt");
        createSymbolicLinkOrSkip(linkedLeaf, outsideKey);
        assertThrows(IOException.class,
                () -> AuthorityFilePreflight.readBoundedRegularFile(
                        root, linkedLeaf, 4096, "test authority key"));

        Path linkedDirectory = root.resolve("linked-directory");
        Files.createSymbolicLink(linkedDirectory, outsideDirectory);
        assertThrows(IOException.class,
                () -> AuthorityFilePreflight.readBoundedRegularFile(
                        root, linkedDirectory.resolve("public.txt"), 4096,
                        "test authority key"));
    }

    @Test
    void posixAuthorityFilesRequireRuntimeOwnerAndExactPrivateModes() throws Exception {
        Path root = AuthorityFilePreflight.createDirectoriesWithoutLinks(
                temporaryDirectory.resolve("private-authority-root"));
        Assumptions.assumeTrue(Files.getFileStore(root).supportsFileAttributeView("posix"));
        AuthorityJournalTestFixture.secureDirectoryIfPosix(root);
        Path file = root.resolve("private.txt");
        Files.writeString(file, "private", StandardCharsets.US_ASCII);
        AuthorityJournalTestFixture.secureFileIfPosix(file);

        assertArrayEquals("private".getBytes(StandardCharsets.US_ASCII),
                AuthorityFilePreflight.readBoundedPrivateRegularFile(
                        root, file, 32, "private test file"));
        Files.setPosixFilePermissions(file, java.util.Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                java.nio.file.attribute.PosixFilePermission.GROUP_READ));
        assertThrows(IOException.class,
                () -> AuthorityFilePreflight.readBoundedPrivateRegularFile(
                        root, file, 32, "private test file"));
    }

    @Test
    void posixIntegrityFilesPermitReadOnlySharingButRejectForeignWriters()
            throws Exception {
        Path root = AuthorityFilePreflight.createDirectoriesWithoutLinks(
                temporaryDirectory.resolve("integrity-root"));
        Assumptions.assumeTrue(Files.getFileStore(root).supportsFileAttributeView("posix"));
        Files.setPosixFilePermissions(root, java.util.Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE,
                java.nio.file.attribute.PosixFilePermission.GROUP_READ,
                java.nio.file.attribute.PosixFilePermission.GROUP_EXECUTE,
                java.nio.file.attribute.PosixFilePermission.OTHERS_READ,
                java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE));
        Path publicPin = root.resolve("proxy-public-key.txt");
        byte[] expected = "public-integrity-pin".getBytes(StandardCharsets.US_ASCII);
        Files.write(publicPin, expected);
        Files.setPosixFilePermissions(publicPin, java.util.Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                java.nio.file.attribute.PosixFilePermission.GROUP_READ,
                java.nio.file.attribute.PosixFilePermission.OTHERS_READ));

        assertArrayEquals(expected,
                AuthorityFilePreflight.readBoundedIntegrityProtectedRegularFile(
                        root, publicPin, 64, "integrity test pin"));

        Files.setPosixFilePermissions(publicPin, java.util.Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                java.nio.file.attribute.PosixFilePermission.GROUP_READ,
                java.nio.file.attribute.PosixFilePermission.GROUP_WRITE));
        assertThrows(IOException.class,
                () -> AuthorityFilePreflight.readBoundedIntegrityProtectedRegularFile(
                        root, publicPin, 64, "integrity test pin"));
    }

    @Test
    void posixPrivateLeafAllowsOwnerControlledApplicationDirectory()
            throws Exception {
        Path root = AuthorityFilePreflight.createDirectoriesWithoutLinks(
                temporaryDirectory.resolve("private-leaf-root"));
        Assumptions.assumeTrue(Files.getFileStore(root).supportsFileAttributeView("posix"));
        Files.setPosixFilePermissions(root, java.util.Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE,
                java.nio.file.attribute.PosixFilePermission.GROUP_READ,
                java.nio.file.attribute.PosixFilePermission.GROUP_EXECUTE,
                java.nio.file.attribute.PosixFilePermission.OTHERS_READ,
                java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE));
        Path privateLeaf = root.resolve("private-key.pk8");
        Files.writeString(privateLeaf, "private", StandardCharsets.US_ASCII);
        AuthorityJournalTestFixture.secureFileIfPosix(privateLeaf);

        assertArrayEquals("private".getBytes(StandardCharsets.US_ASCII),
                AuthorityFilePreflight.readBoundedPrivateLeafRegularFile(
                        root, privateLeaf, 32, "private leaf"));

        Files.setPosixFilePermissions(root, java.util.Set.of(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE,
                java.nio.file.attribute.PosixFilePermission.GROUP_WRITE));
        assertThrows(IOException.class,
                () -> AuthorityFilePreflight.readBoundedPrivateLeafRegularFile(
                        root, privateLeaf, 32, "private leaf"));
    }

    @Test
    void secureAtomicCreationUsesEffectivePrincipalAndRefusesReplacement() throws Exception {
        Path root = AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                temporaryDirectory.resolve("secure-authority-root"),
                "secure test authority root");
        Path file = root.resolve("private.txt");
        byte[] expected = "private-authority-material".getBytes(StandardCharsets.US_ASCII);

        AuthorityFilePreflight.writePrivateFileAtomically(
                root, file, expected, "secure test authority file");
        String originalUserName = System.getProperty("user.name");
        try {
            System.setProperty("user.name", "mcace-spoofed-runtime-name");
            assertArrayEquals(expected, AuthorityFilePreflight.readBoundedPrivateRegularFile(
                    root, file, 64, "secure test authority file"));
        } finally {
            if (originalUserName == null) {
                System.clearProperty("user.name");
            } else {
                System.setProperty("user.name", originalUserName);
            }
        }
        assertThrows(IOException.class, () -> AuthorityFilePreflight.writePrivateFileAtomically(
                root, file, "replacement".getBytes(StandardCharsets.US_ASCII),
                "secure test authority file"));
        assertArrayEquals(expected, Files.readAllBytes(file));
        try (Stream<Path> entries = Files.list(root)) {
            assertTrue(entries.noneMatch(
                    path -> path.getFileName().toString().endsWith(".tmp")));
        }
    }

    @Test
    void secureAtomicReplacementPreservesPrivateContractAndLeavesNoTemporary()
            throws Exception {
        Path root = AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                temporaryDirectory.resolve("replace-authority-root"),
                "replace test authority root");
        Path file = root.resolve("private.txt");
        AuthorityFilePreflight.writePrivateFileAtomically(
                root, file, "first".getBytes(StandardCharsets.US_ASCII),
                "replace test authority file");

        byte[] replacement = "second".getBytes(StandardCharsets.US_ASCII);
        AuthorityFilePreflight.replacePrivateFileAtomically(
                root, file, replacement, "replace test authority file");

        assertArrayEquals(replacement, AuthorityFilePreflight.readBoundedPrivateRegularFile(
                root, file, 32, "replace test authority file"));
        try (Stream<Path> entries = Files.list(root)) {
            assertTrue(entries.noneMatch(
                    path -> path.getFileName().toString().endsWith(".tmp")));
        }
    }

    @Test
    void windowsInheritedBroadDaclFailsClosed() throws Exception {
        Assumptions.assumeTrue(System.getProperty("os.name", "")
                .toLowerCase(Locale.ROOT).contains("windows"));
        Path root = AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                temporaryDirectory.resolve("private-windows-root"),
                "private Windows authority root");
        Path file = root.resolve("private.txt");
        AuthorityFilePreflight.writePrivateFileAtomically(
                root, file, "private".getBytes(StandardCharsets.US_ASCII),
                "private Windows authority file");

        runIcacls(file, "/inheritance:e", "/grant", "*S-1-1-0:(R)");

        assertThrows(IOException.class,
                () -> AuthorityFilePreflight.readBoundedPrivateRegularFile(
                        root, file, 32, "private Windows authority file"));
    }

    @Test
    void windowsIntegrityFileAllowsForeignReadButRejectsForeignWrite() throws Exception {
        Assumptions.assumeTrue(System.getProperty("os.name", "")
                .toLowerCase(Locale.ROOT).contains("windows"));
        Path root = AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                temporaryDirectory.resolve("integrity-windows-root"),
                "integrity Windows root");
        Path file = root.resolve("public.txt");
        byte[] expected = "public".getBytes(StandardCharsets.US_ASCII);
        AuthorityFilePreflight.writePrivateFileAtomically(
                root, file, expected, "integrity Windows file");

        runIcacls(file, "/grant", "*S-1-1-0:(R)");
        assertArrayEquals(expected,
                AuthorityFilePreflight.readBoundedIntegrityProtectedRegularFile(
                        root, file, 32, "integrity Windows file"));

        runIcacls(file, "/grant", "*S-1-1-0:(M)");
        assertThrows(IOException.class,
                () -> AuthorityFilePreflight.readBoundedIntegrityProtectedRegularFile(
                        root, file, 32, "integrity Windows file"));
    }

    @Test
    void windowsJunctionAncestorFailsClosed() throws Exception {
        Assumptions.assumeTrue(System.getProperty("os.name", "")
                .toLowerCase(Locale.ROOT).contains("windows"));
        Path root = AuthorityFilePreflight.createDirectoriesWithoutLinks(
                temporaryDirectory.resolve("authority-root"));
        Path outsideDirectory = Files.createDirectories(temporaryDirectory.resolve("outside"));
        Files.writeString(outsideDirectory.resolve("public.txt"), "outside",
                StandardCharsets.US_ASCII);
        Path junction = root.resolve("junction-directory");
        Process process = new ProcessBuilder(
                "cmd.exe", "/d", "/c", "mklink", "/J",
                junction.toString(), outsideDirectory.toString())
                .redirectErrorStream(true).start();
        int exitCode = process.waitFor();
        Assumptions.assumeTrue(exitCode == 0,
                "Windows junction creation is unavailable: "
                        + new String(process.getInputStream().readAllBytes(),
                        StandardCharsets.UTF_8));

        assertThrows(IOException.class,
                () -> AuthorityFilePreflight.readBoundedRegularFile(
                        root, junction.resolve("public.txt"), 4096,
                        "test authority key"));
        Files.delete(junction);
    }

    private static void createSymbolicLinkOrSkip(Path link, Path target) {
        try {
            Files.createSymbolicLink(link, target);
        } catch (IOException | UnsupportedOperationException | SecurityException exception) {
            Assumptions.assumeTrue(false,
                    "symbolic links are unavailable in this test environment: " + exception);
        }
    }

    private static void runIcacls(Path path, String... arguments) throws Exception {
        String[] command = new String[arguments.length + 2];
        command[0] = Path.of(System.getenv("SystemRoot"), "System32", "icacls.exe").toString();
        command[1] = path.toAbsolutePath().toString();
        System.arraycopy(arguments, 0, command, 2, arguments.length);
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        byte[] output = process.getInputStream().readAllBytes();
        assertTrue(process.waitFor(15, TimeUnit.SECONDS), "icacls ACL mutation timed out");
        assertTrue(process.exitValue() == 0,
                () -> "icacls ACL mutation failed: "
                        + new String(output, StandardCharsets.UTF_8));
    }
}
