package com.ellan.mcace.launcher;

import com.ellan.mcace.protocol.generated.LauncherFile;
import com.ellan.mcace.protocol.launcher.LauncherException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;

public final class LauncherInstaller {
    private static final String CURRENT = "current";
    private static final String STAGING = ".mcace-staging";
    private static final String BACKUP = ".mcace-backup";
    private static final String JOURNAL = ".mcace-update";
    private final Path root;
    private final ContentFetcher fetcher;

    public LauncherInstaller(Path root, ContentFetcher fetcher) {
        this.root = Objects.requireNonNull(root, "root").toAbsolutePath().normalize();
        this.fetcher = Objects.requireNonNull(fetcher, "fetcher");
    }

    public synchronized Path install(VerifiedLauncherManifest verified)
            throws IOException, InterruptedException, LauncherException {
        Objects.requireNonNull(verified, "verified");
        Files.createDirectories(root);
        if (Files.isSymbolicLink(root)) throw new IOException("launcher installation root must not be a symlink");
        recover();
        Path stage = child(STAGING);
        Path backup = child(BACKUP);
        Path current = child(CURRENT);
        deleteTree(stage);
        Files.createDirectory(stage);
        try {
            for (LauncherFile file : verified.manifest().getFilesList()) {
                stageFile(stage, file);
            }
            Files.writeString(stage.resolve(".mcace-manifest.sha256"),
                    HexFormat.of().formatHex(verified.manifestSha256()) + System.lineSeparator(),
                    StandardCharsets.US_ASCII, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            boolean hadCurrent = Files.exists(current, LinkOption.NOFOLLOW_LINKS);
            writeJournal("PREPARED", hadCurrent);
            if (hadCurrent) {
                deleteTree(backup);
                moveAtomic(current, backup);
            }
            writeJournal("BACKED_UP", hadCurrent);
            moveAtomic(stage, current);
            writeJournal("ACTIVATED", hadCurrent);
            deleteTree(backup);
            Files.deleteIfExists(child(JOURNAL));
            return current;
        } catch (IOException | InterruptedException | LauncherException exception) {
            try { recover(); } catch (IOException recovery) { exception.addSuppressed(recovery); }
            throw exception;
        }
    }

    public synchronized void recover() throws IOException {
        Files.createDirectories(root);
        Path current = child(CURRENT);
        Path stage = child(STAGING);
        Path backup = child(BACKUP);
        Path journal = child(JOURNAL);
        if (!Files.exists(journal, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.exists(current, LinkOption.NOFOLLOW_LINKS)
                    && Files.exists(backup, LinkOption.NOFOLLOW_LINKS)) moveAtomic(backup, current);
            else if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) deleteTree(backup);
            deleteTree(stage);
            return;
        }
        Journal value = readJournal();
        switch (value.phase()) {
            case "PREPARED" -> {
                if (!Files.exists(current, LinkOption.NOFOLLOW_LINKS)
                        && Files.exists(backup, LinkOption.NOFOLLOW_LINKS)) moveAtomic(backup, current);
                deleteTree(stage);
            }
            case "BACKED_UP" -> {
                if (value.hadCurrent()) {
                    deleteTree(current);
                    if (!Files.exists(backup, LinkOption.NOFOLLOW_LINKS)) {
                        throw new IOException("launcher recovery backup is missing");
                    }
                    moveAtomic(backup, current);
                } else if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                    deleteTree(stage);
                }
                deleteTree(stage);
            }
            case "ACTIVATED" -> {
                if (!Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException("activated launcher installation is missing");
                }
                deleteTree(stage); deleteTree(backup);
            }
            default -> throw new IOException("launcher update journal phase is invalid");
        }
        Files.deleteIfExists(journal);
    }

    private void stageFile(Path stage, LauncherFile file)
            throws IOException, InterruptedException, LauncherException {
        Path target = stage.resolve(file.getRelativePath()).normalize();
        if (!target.startsWith(stage) || target.equals(stage)) {
            throw new LauncherException("launcher file escapes staging root");
        }
        Files.createDirectories(target.getParent());
        MessageDigest digest = sha256();
        long total = 0;
        try (InputStream input = fetcher.open(URI.create(file.getDownloadUri()));
             OutputStream output = Files.newOutputStream(target,
                     StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) {
                total = Math.addExact(total, read);
                if (total > file.getFileSize()) throw new IOException("launcher file exceeds signed size");
                output.write(buffer, 0, read); digest.update(buffer, 0, read);
            }
        } catch (ArithmeticException exception) {
            throw new IOException("launcher file size overflow", exception);
        }
        if (total != file.getFileSize()
                || !MessageDigest.isEqual(digest.digest(), file.getSha256().toByteArray())) {
            Files.deleteIfExists(target);
            throw new LauncherException("launcher file size or SHA-256 mismatch: " + file.getRelativePath());
        }
        try (FileChannel channel = FileChannel.open(target, StandardOpenOption.WRITE)) { channel.force(true); }
        if (file.getExecutable()) setExecutable(target);
    }

    private void writeJournal(String phase, boolean hadCurrent) throws IOException {
        Path journal = child(JOURNAL);
        Path temporary = Files.createTempFile(root, JOURNAL, ".tmp");
        try {
            Files.writeString(temporary, "version=1\nphase=" + phase + "\nhad_current=" + hadCurrent + "\n",
                    StandardCharsets.US_ASCII, StandardOpenOption.TRUNCATE_EXISTING);
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) { channel.force(true); }
            try { Files.move(temporary, journal, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE); }
            catch (AtomicMoveNotSupportedException exception) {
                throw new IOException("launcher filesystem does not support atomic journal replacement", exception);
            }
        } finally { Files.deleteIfExists(temporary); }
    }

    private Journal readJournal() throws IOException {
        String phase = null;
        Boolean hadCurrent = null;
        for (String line : Files.readAllLines(child(JOURNAL), StandardCharsets.US_ASCII)) {
            if (line.startsWith("phase=")) phase = line.substring(6);
            else if (line.startsWith("had_current=")) {
                String raw = line.substring(12);
                if (!raw.equals("true") && !raw.equals("false")) {
                    throw new IOException("launcher journal boolean is malformed");
                }
                hadCurrent = Boolean.valueOf(raw);
            }
            else if (!line.equals("version=1") && !line.isBlank()) throw new IOException("launcher journal is malformed");
        }
        if (phase == null || hadCurrent == null) throw new IOException("launcher journal is incomplete");
        return new Journal(phase, hadCurrent);
    }

    private Path child(String name) throws IOException {
        Path path = root.resolve(name).normalize();
        if (!path.getParent().equals(root)) throw new IOException("launcher operational path escaped root");
        return path;
    }

    private static void moveAtomic(Path source, Path target) throws IOException {
        try { Files.move(source, target, StandardCopyOption.ATOMIC_MOVE); }
        catch (AtomicMoveNotSupportedException exception) {
            throw new IOException("launcher installation requires same-volume atomic moves", exception);
        }
    }

    private static void deleteTree(Path path) throws IOException {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return;
        if (Files.isSymbolicLink(path) || !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            Files.delete(path); return;
        }
        try (var entries = Files.walk(path)) {
            for (Path entry : entries.sorted(Comparator.reverseOrder()).toList()) Files.delete(entry);
        }
    }

    private static void setExecutable(Path path) throws IOException {
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
            permissions.add(PosixFilePermission.OWNER_EXECUTE);
            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException ignored) {
            // Windows execution is determined by file type, not POSIX mode bits.
        }
    }

    private static MessageDigest sha256() throws LauncherException {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException exception) { throw new LauncherException("SHA-256 is unavailable", exception); }
    }

    private record Journal(String phase, boolean hadCurrent) { }
}
