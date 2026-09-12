package com.ellan.mcace.paper;

import com.ellan.mcace.core.authority.AuthorityFilePreflight;
import com.ellan.mcace.core.authority.ServerAuthorityJournalPreflight;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

/** Test-only authority material provisioning with the production POSIX mode contract. */
final class PaperAuthorityTestFiles {
    private PaperAuthorityTestFiles() {
    }

    static Path privateDirectory(Path parent, String childName) throws IOException {
        return AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                parent.resolve(childName), "Paper test authority private directory");
    }

    static void initializeJournal(Path path) throws IOException {
        writePrivate(path, ServerAuthorityJournalPreflight.requiredInitialContentUtf8());
    }

    static void writePrivateString(Path path, String content, Charset charset)
            throws IOException {
        writePrivate(path, content.getBytes(charset));
    }

    static void writePrivate(Path path, byte[] content) throws IOException {
        Path normalized = path.toAbsolutePath().normalize();
        Path parent = normalized.getParent();
        if (parent == null) {
            throw new IOException("Paper test authority file has no parent");
        }
        AuthorityFilePreflight.requirePrivateDirectory(
                parent, "Paper test authority private directory");
        if (Files.notExists(normalized, LinkOption.NOFOLLOW_LINKS)) {
            AuthorityFilePreflight.writePrivateFileAtomically(
                    parent, normalized, content, "Paper test authority private file");
            return;
        }

        AuthorityFilePreflight.requirePrivateRegularFile(
                parent, normalized, "Paper test authority private file");
        OpenOption[] options = {
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING,
                LinkOption.NOFOLLOW_LINKS
        };
        try (FileChannel channel = FileChannel.open(normalized, options)) {
            ByteBuffer source = ByteBuffer.wrap(content);
            int zeroWrites = 0;
            while (source.hasRemaining()) {
                int count = channel.write(source);
                if (count == 0 && ++zeroWrites > 8) {
                    throw new IOException("Paper test authority write made no progress");
                }
                if (count > 0) {
                    zeroWrites = 0;
                }
            }
            channel.force(true);
        }
        AuthorityFilePreflight.requirePrivateRegularFile(
                parent, normalized, "Paper test authority private file");
    }

    static void secureDirectory(Path path) throws IOException {
        if (supportsPosix(path)) {
            Files.setPosixFilePermissions(path, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE));
        }
    }

    static void secureFile(Path path) throws IOException {
        if (supportsPosix(path)) {
            Files.setPosixFilePermissions(path, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));
        }
    }

    static boolean supportsPosix(Path path) throws IOException {
        return Files.getFileStore(path).supportsFileAttributeView("posix");
    }
}
