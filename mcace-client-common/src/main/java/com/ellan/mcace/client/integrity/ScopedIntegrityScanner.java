package com.ellan.mcace.client.integrity;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.stream.Stream;

public final class ScopedIntegrityScanner {
    private static final byte[] MANIFEST_DOMAIN = "mcace-manifest-v1\0".getBytes(StandardCharsets.UTF_8);

    private final Clock clock;

    public ScopedIntegrityScanner(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public IntegrityManifest scan(Path minecraftRoot, Path relativeScope, ScanPolicy policy)
            throws IntegrityScanException {
        Objects.requireNonNull(minecraftRoot, "minecraftRoot");
        Objects.requireNonNull(relativeScope, "relativeScope");
        Objects.requireNonNull(policy, "policy");
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

        List<Path> files;
        try (Stream<Path> stream = Files.walk(scope)) {
            files = stream
                    .filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
                    .filter(path -> allowed(path, policy))
                    .sorted(Comparator.comparing(path -> portable(scope.relativize(path))))
                    .toList();
        } catch (IOException exception) {
            throw new IntegrityScanException("failed to enumerate scan scope", exception);
        }
        if (files.size() > policy.maxEntries()) {
            throw new IntegrityScanException("scan scope exceeds maximum entry count");
        }

        List<IntegrityEntry> entries = new ArrayList<>(files.size());
        for (Path file : files) {
            try {
                long size = Files.size(file);
                if (size > policy.maxFileBytes()) {
                    throw new IntegrityScanException("file exceeds scan size limit: " + scope.relativize(file));
                }
                entries.add(new IntegrityEntry(portable(scope.relativize(file)), size, sha256(file)));
            } catch (IOException exception) {
                throw new IntegrityScanException("failed to hash file: " + scope.relativize(file), exception);
            }
        }
        return new IntegrityManifest(portable(relativeScope.normalize()), clock.instant(), entries, manifestRoot(entries));
    }

    public ScopeIntegrityManifest scanExplicitFiles(
            Path minecraftRoot,
            String scopeName,
            List<String> relativeFiles,
            ScanPolicy policy,
            boolean required) throws IntegrityScanException {
        Objects.requireNonNull(minecraftRoot, "minecraftRoot");
        Objects.requireNonNull(scopeName, "scopeName");
        Objects.requireNonNull(relativeFiles, "relativeFiles");
        Objects.requireNonNull(policy, "policy");
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
                long size = Files.size(file);
                if (size > policy.maxFileBytes()) {
                    throw new IntegrityScanException("explicit file exceeds scan size limit: " + relative);
                }
                entries.add(new IntegrityEntry(portable(relativePath.normalize()), size, sha256(file)));
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

    private static byte[] sha256(Path file) throws IOException, IntegrityScanException {
        MessageDigest digest = digest();
        byte[] buffer = new byte[64 * 1024];
        try (InputStream input = Files.newInputStream(file)) {
            int read;
            while ((read = input.read(buffer)) >= 0) {
                if (read > 0) {
                    digest.update(buffer, 0, read);
                }
            }
        }
        return digest.digest();
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
            if (Files.isSymbolicLink(current)) {
                throw new IntegrityScanException("symbolic links are not allowed in explicit scopes: " + relative);
            }
        }
    }
}
