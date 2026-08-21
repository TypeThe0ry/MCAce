package com.ellan.mcace.core.authority;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class FileServerAuthorityIssuanceJournalTest {
    private static final String HEADER = "MCACE_SERVER_AUTHORITY_ISSUANCE_JOURNAL_V1";
    private static final String LIFECYCLE = "33".repeat(32);
    private static final Instant OBSERVED = Instant.parse("2026-08-13T00:00:00Z");
    private static final Instant ISSUED = Instant.parse("2026-08-13T00:00:01Z");
    private static final Instant EXPIRES = Instant.parse("2026-08-13T00:00:21Z");

    @TempDir Path directory;

    @Test
    void persistsOnlyContentFreeFixedMetadataAndRecoversSequence() throws Exception {
        Path path = directory.resolve("authority-issuance.log");
        AuthorityJournalTestFixture.initializeEmpty(path);
        try (FileServerAuthorityIssuanceJournal first =
                     new FileServerAuthorityIssuanceJournal(path, 4096)) {
            assertEquals(0L, first.lastSequence(LIFECYCLE));
            first.appendAndForce(record(1, 1, LIFECYCLE, "44".repeat(32)));
            assertEquals(1L, first.lastSequence(LIFECYCLE));
        }

        try (FileServerAuthorityIssuanceJournal reopened =
                     new FileServerAuthorityIssuanceJournal(path, 4096)) {
            assertEquals(1L, reopened.lastSequence(LIFECYCLE));
            reopened.appendAndForce(record(2, 2, LIFECYCLE, "55".repeat(32)));
            assertEquals(2L, reopened.lastSequence(LIFECYCLE));
        }

        String raw = Files.readString(path, StandardCharsets.UTF_8);
        String[] lines = raw.split("\n");
        assertEquals(3, lines.length);
        assertEquals(HEADER, lines[0]);
        assertEquals(10, lines[1].split("\t", -1).length);
        assertTrue(lines[1].startsWith("v1\t00000000-0000-0000-0000-000000000001\t"));
        assertFalse(raw.contains("player.example"));
        assertFalse(raw.contains("authenticated-session"));
        assertFalse(raw.contains("movement-check"));
        assertFalse(raw.contains("route"));
        assertFalse(raw.contains("ban"));
    }

    @Test
    void rejectsDuplicateAttestationFrameAndNonIncreasingLifecycleSequence() throws Exception {
        Path path = directory.resolve("duplicates.log");
        AuthorityJournalTestFixture.initializeEmpty(path);
        try (FileServerAuthorityIssuanceJournal journal =
                     new FileServerAuthorityIssuanceJournal(path, 8192)) {
            ServerAuthorityIssuanceRecord first =
                    record(1, 4, LIFECYCLE, "44".repeat(32));
            journal.appendAndForce(first);

            assertThrows(IOException.class, () -> journal.appendAndForce(first));
            assertThrows(IOException.class, () -> journal.appendAndForce(
                    record(2, 4, LIFECYCLE, "55".repeat(32))));
            assertThrows(IOException.class, () -> journal.appendAndForce(
                    record(3, 3, LIFECYCLE, "66".repeat(32))));
            assertThrows(IOException.class, () -> journal.appendAndForce(
                    record(4, 5, "77".repeat(32), "44".repeat(32))));
            assertEquals(4L, journal.lastSequence(LIFECYCLE));
        }
        assertEquals(2, Files.readAllLines(path, StandardCharsets.UTF_8).size());
    }

    @Test
    void missingEmptyCorruptNonUtf8AndOverQuotaJournalsFailClosed() throws Exception {
        Path missing = directory.resolve("missing.log");
        assertThrows(IOException.class,
                () -> new FileServerAuthorityIssuanceJournal(missing, 4096));

        Path empty = directory.resolve("empty.log");
        Files.createFile(empty);
        assertThrows(IOException.class,
                () -> new FileServerAuthorityIssuanceJournal(empty, 4096));

        Path corrupt = directory.resolve("corrupt.log");
        AuthorityJournalTestFixture.initializeEmpty(corrupt);
        Files.writeString(corrupt, "v1\tpartial", StandardCharsets.UTF_8,
                StandardOpenOption.APPEND);
        assertThrows(IOException.class,
                () -> new FileServerAuthorityIssuanceJournal(corrupt, 4096));

        Path nonUtf8 = directory.resolve("non-utf8.log");
        AuthorityJournalTestFixture.initializeEmpty(nonUtf8);
        Files.write(nonUtf8, new byte[] {(byte) 0xc3, (byte) 0x28, (byte) '\n'},
                StandardOpenOption.APPEND);
        assertThrows(IOException.class,
                () -> new FileServerAuthorityIssuanceJournal(nonUtf8, 4096));

        Path quota = directory.resolve("quota.log");
        AuthorityJournalTestFixture.initializeEmpty(quota);
        long initialSize = Files.size(quota);
        try (FileServerAuthorityIssuanceJournal tiny =
                     new FileServerAuthorityIssuanceJournal(quota, 64)) {
            assertThrows(IOException.class, () -> tiny.appendAndForce(
                    record(1, 1, LIFECYCLE, "44".repeat(32))));
        }
        assertEquals(initialSize, Files.size(quota));
    }

    @Test
    void nonRegularTargetAndEverySymlinkPositionAreRejected() throws Exception {
        Files.createDirectory(directory.resolve("directory-target"));
        assertThrows(IOException.class, () -> new FileServerAuthorityIssuanceJournal(
                directory.resolve("directory-target"), 4096));

        Path target = directory.resolve("real.log");
        AuthorityJournalTestFixture.initializeEmpty(target);
        Path link = directory.resolve("linked.log");
        try {
            Files.createSymbolicLink(link, target);
        } catch (IOException | UnsupportedOperationException | SecurityException exception) {
            Assumptions.abort("symbolic links unavailable: "
                    + exception.getClass().getSimpleName());
        }
        assertThrows(IOException.class,
                () -> new FileServerAuthorityIssuanceJournal(link, 4096));

        Path realParent = Files.createDirectory(directory.resolve("real-parent"));
        AuthorityJournalTestFixture.initializeEmpty(realParent.resolve("journal.log"));
        Path linkedParent = directory.resolve("linked-parent");
        Files.createSymbolicLink(linkedParent, realParent);
        assertThrows(IOException.class, () -> new FileServerAuthorityIssuanceJournal(
                linkedParent.resolve("journal.log"), 4096));
    }

    @Test
    void longLivedLockRejectsASecondJournalUntilClose() throws Exception {
        Path path = directory.resolve("locked.log");
        AuthorityJournalTestFixture.initializeEmpty(path);
        try (FileServerAuthorityIssuanceJournal first =
                     new FileServerAuthorityIssuanceJournal(path, 8192)) {
            assertThrows(IOException.class,
                    () -> new FileServerAuthorityIssuanceJournal(path, 8192));
            assertThrows(IOException.class,
                    () -> ServerAuthorityJournalPreflight.verify(path, 8192));
            first.appendAndForce(record(1, 1, LIFECYCLE, "44".repeat(32)));
        }
        try (FileServerAuthorityIssuanceJournal reopened =
                     new FileServerAuthorityIssuanceJournal(path, 8192)) {
            assertEquals(1L, reopened.lastSequence(LIFECYCLE));
        }
    }

    @Test
    void longLivedLockRejectsAnIndependentJvmUntilClose() throws Exception {
        Path path = directory.resolve("independent-jvm-locked.log");
        AuthorityJournalTestFixture.initializeEmpty(path);

        try (FileServerAuthorityIssuanceJournal journal =
                     new FileServerAuthorityIssuanceJournal(path, 8192)) {
            assertEquals(path.toAbsolutePath().normalize(), journal.path());
            ProcessResult whileLocked = runIndependentJvmProbe(path);
            assertEquals(FileServerAuthorityIssuanceJournalProcessProbe.LOCKED_EXIT_CODE,
                    whileLocked.exitCode(), whileLocked.output());
        }

        ProcessResult afterClose = runIndependentJvmProbe(path);
        assertEquals(0, afterClose.exitCode(), afterClose.output());
    }

    @Test
    void replacementIsEitherPreventedOrPoisonsTheOpenJournal() throws Exception {
        Path path = directory.resolve("replace.log");
        Path replacement = directory.resolve("replacement.log");
        AuthorityJournalTestFixture.initializeEmpty(path);
        AuthorityJournalTestFixture.initializeEmpty(replacement);
        try (FileServerAuthorityIssuanceJournal journal =
                     new FileServerAuthorityIssuanceJournal(path, 8192)) {
            boolean replaced = false;
            try {
                Files.move(replacement, path, StandardCopyOption.REPLACE_EXISTING);
                replaced = true;
            } catch (IOException expectedOnNoShareDeletePlatforms) {
                assertEquals(0L, journal.lastSequence(LIFECYCLE));
            }
            if (replaced) {
                assertThrows(IOException.class, () -> journal.lastSequence(LIFECYCLE));
                assertThrows(IOException.class, () -> journal.appendAndForce(
                        record(1, 1, LIFECYCLE, "44".repeat(32))));
            }
        }
    }

    @Test
    void externalWriteIsEitherPreventedOrPoisonsTheOpenJournal() throws Exception {
        Path path = directory.resolve("external-write.log");
        AuthorityJournalTestFixture.initializeEmpty(path);
        try (FileServerAuthorityIssuanceJournal journal =
                     new FileServerAuthorityIssuanceJournal(path, 8192)) {
            boolean written = false;
            try {
                Files.writeString(path, "tamper\n", StandardCharsets.UTF_8,
                        StandardOpenOption.APPEND);
                written = true;
            } catch (IOException expectedOnNoShareWritePlatforms) {
                assertEquals(0L, journal.lastSequence(LIFECYCLE));
            }
            if (written) {
                assertThrows(IOException.class, () -> journal.lastSequence(LIFECYCLE));
                assertThrows(IOException.class, () -> journal.appendAndForce(
                        record(1, 1, LIFECYCLE, "44".repeat(32))));
            }
        }
    }

    @Test
    void publicPreflightIsReadOnlyAndWriteMethodsRemainPackageConfined() throws Exception {
        Path path = directory.resolve("preflight.log");
        assertThrows(IOException.class,
                () -> ServerAuthorityJournalPreflight.verify(path, 8192));
        assertFalse(Files.exists(path));

        byte[] required = ServerAuthorityJournalPreflight.requiredInitialContentUtf8();
        assertEquals(HEADER + "\n", new String(required, StandardCharsets.UTF_8));
        required[0] ^= 1;
        assertEquals(HEADER + "\n", new String(
                ServerAuthorityJournalPreflight.requiredInitialContentUtf8(),
                StandardCharsets.UTF_8));
        AuthorityJournalTestFixture.initializeEmpty(path);
        long sizeBefore = Files.size(path);
        ServerAuthorityJournalPreflight.verify(path, 8192);
        assertEquals(sizeBefore, Files.size(path));

        Path badHeader = directory.resolve("preflight-bad-header.log");
        Files.writeString(badHeader, "wrong\n", StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW);
        assertThrows(IOException.class,
                () -> ServerAuthorityJournalPreflight.verify(badHeader, 8192));

        assertFalse(Modifier.isPublic(FileServerAuthorityIssuanceJournal.class
                .getDeclaredMethod("appendAndForce", ServerAuthorityIssuanceRecord.class)
                .getModifiers()));
        assertFalse(Modifier.isPublic(FileServerAuthorityIssuanceJournal.class
                .getDeclaredMethod("lastSequence", String.class).getModifiers()));
        assertThrows(NoSuchMethodException.class, () ->
                FileServerAuthorityIssuanceJournal.class.getDeclaredMethod(
                        "initializeEmpty", Path.class));
        assertTrue(Modifier.isAbstract(ServerAuthorityIssuanceJournal.class
                .getDeclaredMethod("lastSequence", String.class).getModifiers()));
    }

    private static ServerAuthorityIssuanceRecord record(
            int id, long sequence, String lifecycle, String frame) {
        return new ServerAuthorityIssuanceRecord(
                UUID.fromString("00000000-0000-0000-0000-" + String.format("%012d", id)),
                "11".repeat(32), sequence, lifecycle, "22".repeat(32), OBSERVED, ISSUED,
                EXPIRES, frame);
    }

    private static ProcessResult runIndependentJvmProbe(Path path) throws Exception {
        Process process = new ProcessBuilder(
                javaExecutable().toString(),
                "-cp",
                probeClassPath(),
                FileServerAuthorityIssuanceJournalProcessProbe.class.getName(),
                path.toAbsolutePath().normalize().toString())
                .redirectErrorStream(true)
                .start();
        if (!process.waitFor(20, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            process.waitFor(5, TimeUnit.SECONDS);
            throw new AssertionError("independent JVM journal probe timed out");
        }
        String output = new String(process.getInputStream().readAllBytes(),
                StandardCharsets.UTF_8);
        return new ProcessResult(process.exitValue(), output);
    }

    private static Path javaExecutable() {
        Path bin = Path.of(System.getProperty("java.home"), "bin");
        Path executable = bin.resolve("java");
        return Files.isRegularFile(executable) ? executable : bin.resolve("java.exe");
    }

    private static String probeClassPath() throws Exception {
        Set<String> entries = new LinkedHashSet<>();
        entries.add(codeSource(FileServerAuthorityIssuanceJournalProcessProbe.class));
        entries.add(codeSource(FileServerAuthorityIssuanceJournal.class));
        return String.join(File.pathSeparator, entries);
    }

    private static String codeSource(Class<?> type) throws Exception {
        return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI())
                .toString();
    }

    private record ProcessResult(int exitCode, String output) {
    }
}

/** Independent-process probe for the lifetime-lock contract. */
final class FileServerAuthorityIssuanceJournalProcessProbe {
    static final int LOCKED_EXIT_CODE = 23;

    private FileServerAuthorityIssuanceJournalProcessProbe() {
    }

    public static void main(String[] arguments) throws Exception {
        if (arguments.length != 1) {
            throw new IllegalArgumentException("expected one journal path");
        }
        Path expected = Path.of(arguments[0]).toAbsolutePath().normalize();
        try (FileServerAuthorityIssuanceJournal journal =
                     new FileServerAuthorityIssuanceJournal(Path.of(arguments[0]), 8192)) {
            if (!expected.equals(journal.path())) {
                throw new IOException("journal probe opened an unexpected path");
            }
        } catch (IOException expectedWhileLocked) {
            System.exit(LOCKED_EXIT_CODE);
        }
    }
}
