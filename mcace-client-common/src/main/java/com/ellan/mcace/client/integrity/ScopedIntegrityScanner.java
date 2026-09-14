package com.ellan.mcace.client.integrity;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

public final class ScopedIntegrityScanner {
    private static final byte[] MANIFEST_DOMAIN = "mcace-manifest-v1\0".getBytes(StandardCharsets.UTF_8);
    private static final int HASH_CHUNK_BYTES = 64 * 1024;

    private final Clock clock;
    private final FileChannelOpener channelOpener;

    public ScopedIntegrityScanner(Clock clock) {
        this(clock, file -> FileChannel.open(
                file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));
    }

    ScopedIntegrityScanner(Clock clock, FileChannelOpener channelOpener) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.channelOpener = Objects.requireNonNull(channelOpener, "channelOpener");
    }

    public IntegrityManifest scan(Path minecraftRoot, Path relativeScope, ScanPolicy policy)
            throws IntegrityScanException {
        return scan(minecraftRoot, relativeScope, policy, IntegrityScanCancellation.NONE);
    }

    public IntegrityManifest scan(Path minecraftRoot, Path relativeScope, ScanPolicy policy,
            IntegrityScanCancellation cancellation) throws IntegrityScanException {
        Objects.requireNonNull(minecraftRoot, "minecraftRoot");
        Objects.requireNonNull(relativeScope, "relativeScope");
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(cancellation, "cancellation");
        cancellation.check();
        if (relativeScope.isAbsolute()) {
            throw new IntegrityScanException("scan scope must be relative to the Minecraft root");
        }

        Path normalizedRoot = minecraftRoot.toAbsolutePath().normalize();
        Path scope = normalizedRoot.resolve(relativeScope).normalize();
        if (!scope.startsWith(normalizedRoot)) {
            throw new IntegrityScanException("scan scope escapes the Minecraft root");
        }
        if (!Files.isDirectory(scope, LinkOption.NOFOLLOW_LINKS)) {
            throw new IntegrityScanException("scan scope is not a directory: " + relativeScope);
        }
        Path realRoot;
        try {
            realRoot = normalizedRoot.toRealPath();
        } catch (IOException exception) {
            throw new IntegrityScanException("Minecraft root is unavailable", exception);
        }

        List<Path> files = new ArrayList<>();
        try {
            Files.walkFileTree(scope, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes)
                        throws IOException {
                    checkTraversalCancellation(cancellation);
                    if (!attributes.isDirectory() || attributes.isSymbolicLink() || attributes.isOther()) {
                        throw traversalRejected("reparse/special directories are not allowed in integrity scopes");
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attributes)
                        throws IOException {
                    checkTraversalCancellation(cancellation);
                    if (attributes.isSymbolicLink() || attributes.isOther()) {
                        throw traversalRejected("reparse/special files are not allowed in integrity scopes");
                    }
                    if (attributes.isRegularFile() && allowed(file, policy)) {
                        files.add(file);
                        if (files.size() > policy.maxEntries()) {
                            throw traversalRejected("scan scope exceeds maximum entry count");
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exception) throws IOException {
                    throw exception;
                }
            });
        } catch (TraversalRejected exception) {
            throw exception.integrityFailure;
        } catch (IOException exception) {
            throw new IntegrityScanException("failed to enumerate scan scope", exception);
        }
        files.sort(Comparator.comparing(path -> portable(scope.relativize(path))));

        List<IntegrityEntry> entries = new ArrayList<>(files.size());
        for (Path file : files) {
            cancellation.check();
            try {
                rejectSymlinkSegments(normalizedRoot, file);
                HashedFile hashed = hashStableRegularFile(
                        file, normalizedRoot, realRoot, policy.maxFileBytes(), cancellation);
                entries.add(new IntegrityEntry(
                        portable(scope.relativize(file)), hashed.size(), hashed.sha256()));
            } catch (IOException exception) {
                throw new IntegrityScanException("failed to hash file: " + scope.relativize(file), exception);
            }
        }
        cancellation.check();
        return new IntegrityManifest(portable(relativeScope.normalize()), clock.instant(), entries, manifestRoot(entries));
    }

    public ScopeIntegrityManifest scanExplicitFiles(
            Path minecraftRoot,
            String scopeName,
            List<String> relativeFiles,
            ScanPolicy policy,
            boolean required) throws IntegrityScanException {
        return scanExplicitFiles(minecraftRoot, scopeName, relativeFiles, policy, required,
                IntegrityScanCancellation.NONE);
    }

    public ScopeIntegrityManifest scanExplicitFiles(
            Path minecraftRoot,
            String scopeName,
            List<String> relativeFiles,
            ScanPolicy policy,
            boolean required,
            IntegrityScanCancellation cancellation) throws IntegrityScanException {
        Objects.requireNonNull(minecraftRoot, "minecraftRoot");
        Objects.requireNonNull(scopeName, "scopeName");
        Objects.requireNonNull(relativeFiles, "relativeFiles");
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(cancellation, "cancellation");
        cancellation.check();
        if (scopeName.isBlank() || relativeFiles.isEmpty() || relativeFiles.size() > policy.maxEntries()) {
            throw new IntegrityScanException("explicit scope definition is invalid");
        }
        Path normalizedRoot = minecraftRoot.toAbsolutePath().normalize();
        Path realRoot;
        try {
            realRoot = normalizedRoot.toRealPath();
        } catch (IOException exception) {
            throw new IntegrityScanException("Minecraft root is unavailable", exception);
        }
        List<IntegrityEntry> entries = new ArrayList<>();
        for (String relative : relativeFiles.stream().distinct().sorted().toList()) {
            cancellation.check();
            Path relativePath = Path.of(relative);
            if (relativePath.isAbsolute()) {
                throw new IntegrityScanException("explicit file path must be relative: " + relative);
            }
            Path file = normalizedRoot.resolve(relativePath).normalize();
            if (!file.startsWith(normalizedRoot)) {
                throw new IntegrityScanException("explicit file escapes Minecraft root: " + relative);
            }
            if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
                if (required) {
                    throw new IntegrityScanException("required explicit file is missing: " + relative);
                }
                continue;
            }
            rejectSymlinkSegments(normalizedRoot, file);
            try {
                Path realFile = file.toRealPath();
                if (!realFile.startsWith(realRoot)
                        || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                        || !allowed(file, policy)) {
                    throw new IntegrityScanException("explicit file is outside policy: " + relative);
                }
                HashedFile hashed = hashStableRegularFile(
                        file, normalizedRoot, realRoot, policy.maxFileBytes(), cancellation);
                entries.add(new IntegrityEntry(
                        portable(relativePath.normalize()), hashed.size(), hashed.sha256()));
            } catch (IOException exception) {
                throw new IntegrityScanException("failed to hash explicit file: " + relative, exception);
            }
        }
        boolean present = !entries.isEmpty();
        return new ScopeIntegrityManifest(
                scopeName,
                "",
                present,
                clock.instant(),
                entries,
                manifestRoot(entries));
    }

    private static boolean allowed(Path path, ScanPolicy policy) {
        if (policy.allowedExtensions().isEmpty()) {
            return true;
        }
        String filename = path.getFileName().toString().toLowerCase(Locale.ROOT);
        return policy.allowedExtensions().stream().anyMatch(filename::endsWith);
    }

    private HashedFile hashStableRegularFile(Path file, Path lexicalRoot, Path realRoot,
            long maxFileBytes, IntegrityScanCancellation cancellation)
            throws IOException, IntegrityScanException {
        cancellation.check();
        BasicFileAttributes before = Files.readAttributes(
                file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Path realBefore = file.toRealPath();
        if (!before.isRegularFile() || before.isSymbolicLink() || !realBefore.startsWith(realRoot)) {
            throw new IntegrityScanException("file is not a stable regular file inside the scan root");
        }

        HashedFile firstRead = hashNoFollowHandle(
                file, before.size(), maxFileBytes, cancellation);
        cancellation.check();
        rejectSymlinkSegments(lexicalRoot, file);
        BasicFileAttributes between = Files.readAttributes(
                file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Path realBetween = file.toRealPath();
        if (!stableAttributes(before, between) || !realBefore.equals(realBetween)) {
            throw new IntegrityScanException("file changed while it was being hashed");
        }

        // FileChannel exposes size/content from its handle, but the standard Windows provider
        // does not expose BasicFileAttributes/fileKey for that handle. A second independent
        // NOFOLLOW_LINKS open adds a fail-closed verification pass for that binding gap: both
        // handles must produce identical size/content with stable path attributes and parent
        // segments around both reads.
        HashedFile secondRead = hashNoFollowHandle(
                file, between.size(), maxFileBytes, cancellation);
        cancellation.check();
        rejectSymlinkSegments(lexicalRoot, file);
        BasicFileAttributes after = Files.readAttributes(
                file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        Path realAfter = file.toRealPath();
        if (!stableAttributes(between, after) || !realBetween.equals(realAfter)
                || firstRead.size() != secondRead.size()
                || !MessageDigest.isEqual(firstRead.sha256(), secondRead.sha256())) {
            throw new IntegrityScanException("file changed between its verified no-follow reads");
        }
        return firstRead;
    }

    private HashedFile hashNoFollowHandle(Path file, long expectedSize, long maxFileBytes,
            IntegrityScanCancellation cancellation) throws IOException, IntegrityScanException {
        MessageDigest digest = digest();
        long openedSize;
        long finalHandleSize;
        long readBytes = 0L;
        ByteBuffer buffer = ByteBuffer.allocate(HASH_CHUNK_BYTES);
        cancellation.check();
        try (SeekableByteChannel channel = channelOpener.open(file)) {
            openedSize = channel.size();
            if (openedSize < 0L || openedSize > maxFileBytes || openedSize != expectedSize) {
                throw new IntegrityScanException("file exceeds its scan limit or changed before opening");
            }
            while (true) {
                cancellation.check();
                buffer.clear();
                int read = channel.read(buffer);
                if (read < 0) {
                    break;
                }
                if (read == 0) {
                    continue;
                }
                readBytes = Math.addExact(readBytes, read);
                if (readBytes > maxFileBytes) {
                    throw new IntegrityScanException("file grew beyond its scan size limit");
                }
                buffer.flip();
                digest.update(buffer);
            }
            cancellation.check();
            finalHandleSize = channel.size();
        }
        if (openedSize != finalHandleSize || openedSize != readBytes) {
            throw new IntegrityScanException("file size changed on its open handle");
        }
        return new HashedFile(openedSize, digest.digest());
    }

    private static boolean stableAttributes(BasicFileAttributes before, BasicFileAttributes after) {
        return after.isRegularFile() && !after.isSymbolicLink()
                && before.size() == after.size()
                && before.creationTime().equals(after.creationTime())
                && before.lastModifiedTime().equals(after.lastModifiedTime())
                && Objects.equals(before.fileKey(), after.fileKey());
    }

    static byte[] manifestRoot(List<IntegrityEntry> entries) throws IntegrityScanException {
        MessageDigest digest = digest();
        digest.update(MANIFEST_DOMAIN);
        for (IntegrityEntry entry : entries) {
            byte[] path = entry.relativePath().getBytes(StandardCharsets.UTF_8);
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(path.length).array());
            digest.update(path);
            digest.update(ByteBuffer.allocate(Long.BYTES).putLong(entry.fileSize()).array());
            digest.update(entry.sha256());
        }
        return digest.digest();
    }

    private static MessageDigest digest() throws IntegrityScanException {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IntegrityScanException("SHA-256 is unavailable", exception);
        }
    }

    private static String portable(Path path) {
        return path.toString().replace('\\', '/');
    }

    private static void rejectSymlinkSegments(Path root, Path file) throws IntegrityScanException {
        Path current = root;
        Path relative = root.relativize(file);
        for (Path segment : relative) {
            current = current.resolve(segment);
            final BasicFileAttributes attributes;
            try {
                attributes = Files.readAttributes(
                        current, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            } catch (IOException exception) {
                throw new IntegrityScanException(
                        "could not verify an integrity-scope path segment: " + relative, exception);
            }
            if (attributes.isSymbolicLink() || attributes.isOther()) {
                throw new IntegrityScanException(
                        "reparse/special path segments are not allowed in integrity scopes: " + relative);
            }
        }
    }

    private static void checkTraversalCancellation(IntegrityScanCancellation cancellation)
            throws TraversalRejected {
        try {
            cancellation.check();
        } catch (IntegrityScanException exception) {
            throw new TraversalRejected(exception);
        }
    }

    private static TraversalRejected traversalRejected(String message) {
        return new TraversalRejected(new IntegrityScanException(message));
    }

    private static final class TraversalRejected extends IOException {
        private static final long serialVersionUID = 1L;
        private final IntegrityScanException integrityFailure;

        private TraversalRejected(IntegrityScanException integrityFailure) {
            super(integrityFailure.getMessage(), integrityFailure);
            this.integrityFailure = integrityFailure;
        }
    }

    @FunctionalInterface
    interface FileChannelOpener {
        SeekableByteChannel open(Path file) throws IOException;
    }

    private record HashedFile(long size, byte[] sha256) { }
}
