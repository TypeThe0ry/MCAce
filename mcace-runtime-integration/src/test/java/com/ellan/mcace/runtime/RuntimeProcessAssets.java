package com.ellan.mcace.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Properties;

/** Strict, property-only runtime assets for an enabled real-process gate. */
record RuntimeProcessAssets(
        String backendKind,
        String proxyKind,
        MinecraftWireProfile wireProfile,
        Path backendJar,
        String backendJarSha256,
        Path preparedRoot,
        String preparedRootSha256,
        Path serverJava,
        String serverJavaSha256,
        Path proxyJar,
        String proxyJarSha256) {

    private static final String PREFIX = "mcace.runtime.";
    private static final byte[] PREPARED_TREE_DOMAIN =
            "MCACE_PREPARED_TREE_SHA256_V1\0".getBytes(StandardCharsets.US_ASCII);

    static RuntimeProcessAssets fromSystemProperties(String expectedBackendKind, String proxyKind) {
        try {
            return fromProperties(System.getProperties(), expectedBackendKind, proxyKind);
        } catch (IOException exception) {
            throw new IllegalArgumentException(
                    "RUNTIME_ASSET_PREFLIGHT_FAILED|" + exception.getMessage(), exception);
        }
    }

    static RuntimeProcessAssets fromProperties(
            Properties properties,
            String expectedBackendKind,
            String proxyKind) throws IOException {
        Objects.requireNonNull(properties, "properties");
        BackendAssets backend = backendFromProperties(properties, expectedBackendKind);

        String normalizedProxy = normalizeKind(proxyKind, "proxyKind");
        if (!normalizedProxy.equals("VELOCITY") && !normalizedProxy.equals("BUNGEE")) {
            throw new IllegalArgumentException("RUNTIME_PROXY_KIND_UNSUPPORTED|" + normalizedProxy);
        }

        String proxyPrefix = PREFIX + normalizedProxy.toLowerCase(Locale.ROOT);
        VerifiedFile proxyJar = verifiedFile(
                properties, proxyPrefix + ".jar", proxyPrefix + ".jar.sha256");

        return new RuntimeProcessAssets(
                backend.backendKind(),
                normalizedProxy,
                backend.wireProfile(),
                backend.backendJar(),
                backend.backendJarSha256(),
                backend.preparedRoot(),
                backend.preparedRootSha256(),
                backend.serverJava(),
                backend.serverJavaSha256(),
                proxyJar.path(),
                proxyJar.sha256());
    }

    static BackendAssets backendFromSystemProperties(String expectedBackendKind) {
        try {
            return backendFromProperties(System.getProperties(), expectedBackendKind);
        } catch (IOException exception) {
            throw new IllegalArgumentException(
                    "RUNTIME_ASSET_PREFLIGHT_FAILED|" + exception.getMessage(), exception);
        }
    }

    static BackendAssets backendFromProperties(
            Properties properties, String expectedBackendKind) throws IOException {
        Objects.requireNonNull(properties, "properties");
        String expectedBackend = normalizeKind(expectedBackendKind, "expectedBackendKind");
        String configuredBackend = normalizeKind(
                required(properties, PREFIX + "backend-kind"), "mcace.runtime.backend-kind");
        if (!configuredBackend.equals(expectedBackend)) {
            throw new IllegalArgumentException(
                    "RUNTIME_BACKEND_KIND_MISMATCH|expected=" + expectedBackend
                            + "|configured=" + configuredBackend);
        }

        String minecraftVersion = required(properties, PREFIX + "minecraft-version");
        int protocol = requiredPositiveInt(properties, PREFIX + "minecraft-protocol");
        int serverJavaFeature = requiredPositiveInt(properties, PREFIX + "server-java-feature");
        MinecraftWireProfile wireProfile = MinecraftWireProfile.forMinecraftVersion(minecraftVersion);
        if (!MinecraftWireProfile.releaseProfiles().contains(wireProfile)) {
            throw new IllegalArgumentException(
                    "RUNTIME_MINECRAFT_VERSION_OUTSIDE_RELEASE_MATRIX|version=" + minecraftVersion);
        }
        if (wireProfile.protocolVersion() != protocol
                || MinecraftWireProfile.forProtocolVersion(protocol) != wireProfile) {
            throw new IllegalArgumentException(
                    "RUNTIME_MINECRAFT_PROTOCOL_MISMATCH|version=" + minecraftVersion
                            + "|configured=" + protocol
                            + "|expected=" + wireProfile.protocolVersion());
        }
        if (wireProfile.requiredServerJavaFeature() != serverJavaFeature) {
            throw new IllegalArgumentException(
                    "RUNTIME_SERVER_JAVA_FEATURE_MISMATCH|minecraft=" + minecraftVersion
                            + "|configured=" + serverJavaFeature
                            + "|expected=" + wireProfile.requiredServerJavaFeature());
        }

        VerifiedFile backendJar = verifiedFile(
                properties, PREFIX + "backend.jar", PREFIX + "backend.jar.sha256");
        VerifiedDirectory preparedRoot = verifiedPreparedRoot(
                properties,
                PREFIX + "backend.prepared-root",
                PREFIX + "backend.prepared-root.sha256");
        VerifiedFile serverJava = verifiedFile(
                properties, PREFIX + "server-java", PREFIX + "server-java.sha256");
        return new BackendAssets(
                configuredBackend,
                wireProfile,
                backendJar.path(),
                backendJar.sha256(),
                preparedRoot.path(),
                preparedRoot.sha256(),
                serverJava.path(),
                serverJava.sha256());
    }

    RuntimeProcessAssets {
        backendKind = normalizeKind(backendKind, "backendKind");
        proxyKind = normalizeKind(proxyKind, "proxyKind");
        wireProfile = Objects.requireNonNull(wireProfile, "wireProfile");
        backendJar = Objects.requireNonNull(backendJar, "backendJar");
        backendJarSha256 = normalizeSha256(backendJarSha256, "backendJarSha256");
        preparedRoot = Objects.requireNonNull(preparedRoot, "preparedRoot");
        preparedRootSha256 = normalizeSha256(preparedRootSha256, "preparedRootSha256");
        serverJava = Objects.requireNonNull(serverJava, "serverJava");
        serverJavaSha256 = normalizeSha256(serverJavaSha256, "serverJavaSha256");
        proxyJar = Objects.requireNonNull(proxyJar, "proxyJar");
        proxyJarSha256 = normalizeSha256(proxyJarSha256, "proxyJarSha256");
    }

    private static VerifiedFile verifiedFile(
            Properties properties, String pathProperty, String sha256Property) throws IOException {
        Path path = directPath(required(properties, pathProperty), pathProperty);
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("RUNTIME_ASSET_FILE_MISSING|" + pathProperty + "=" + path);
        }
        String expected = normalizeSha256(required(properties, sha256Property), sha256Property);
        String actual = sha256(path);
        if (!MessageDigest.isEqual(
                HexFormat.of().parseHex(expected), HexFormat.of().parseHex(actual))) {
            throw new IllegalArgumentException(
                    "RUNTIME_ASSET_SHA256_MISMATCH|" + pathProperty
                            + "|expected=" + expected + "|actual=" + actual);
        }
        return new VerifiedFile(path, actual);
    }

    private static VerifiedDirectory verifiedPreparedRoot(
            Properties properties,
            String pathProperty,
            String sha256Property) throws IOException {
        Path root = directPath(required(properties, pathProperty), pathProperty);
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException(
                    "RUNTIME_PREPARED_ROOT_MISSING|" + pathProperty + "=" + root);
        }
        // Bind the immutable bootstrap payload rather than one historical world layout. Folia
        // 1.21.11 creates root world_nether/world_the_end directories, while 26.1+ stores those
        // dimensions below the single world directory. cache/libraries/versions are the actual
        // offline-runtime prerequisites; an isolated run may create its worlds after the copy.
        List<String> requiredDirectories = List.of("cache", "libraries", "versions");
        for (String requiredDirectory : requiredDirectories) {
            Path child = root.resolve(requiredDirectory);
            if (!Files.isDirectory(child, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(child)) {
                throw new IllegalArgumentException(
                        "RUNTIME_PREPARED_ROOT_INCOMPLETE|missing=" + requiredDirectory + "|root=" + root);
            }
        }
        String expected = normalizeSha256(required(properties, sha256Property), sha256Property);
        String actual = preparedTreeSha256(root);
        if (!MessageDigest.isEqual(
                HexFormat.of().parseHex(expected), HexFormat.of().parseHex(actual))) {
            throw new IllegalArgumentException(
                    "RUNTIME_PREPARED_ROOT_SHA256_MISMATCH|expected=" + expected
                            + "|actual=" + actual + "|root=" + root);
        }
        return new VerifiedDirectory(root, actual);
    }

    static String sha256(Path path) throws IOException {
        MessageDigest digest = sha256Digest();
        try (InputStream input = Files.newInputStream(path)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                if (read > 0) digest.update(buffer, 0, read);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    /**
     * Hashes the immutable prepared-runtime roots ({@code cache}, {@code libraries}, and
     * {@code versions}), sorted by slash-normalized relative path. Generated worlds, logs, and
     * configuration are deliberately outside this contract. Each file contributes path-length,
     * path bytes, size, then raw bytes after a domain prefix. Symlinks and unknown entries below
     * the three roots are rejected.
     */
    static String preparedTreeSha256(Path root) throws IOException {
        Path normalizedRoot = root.toAbsolutePath().normalize();
        if (Files.isSymbolicLink(normalizedRoot)) {
            throw new IllegalArgumentException("RUNTIME_ASSET_SYMLINK_REJECTED|" + normalizedRoot);
        }
        List<Path> files = new ArrayList<>();
        for (String requiredDirectory : List.of("cache", "libraries", "versions")) {
            Path preparedDirectory = normalizedRoot.resolve(requiredDirectory);
            if (!Files.isDirectory(preparedDirectory, LinkOption.NOFOLLOW_LINKS)
                    || Files.isSymbolicLink(preparedDirectory)) {
                throw new IllegalArgumentException(
                        "RUNTIME_PREPARED_ROOT_INCOMPLETE|missing=" + requiredDirectory
                                + "|root=" + normalizedRoot);
            }
            try (var walk = Files.walk(preparedDirectory)) {
                for (Path entry : walk.toList()) {
                    if (Files.isSymbolicLink(entry)) {
                        throw new IllegalArgumentException("RUNTIME_ASSET_SYMLINK_REJECTED|" + entry);
                    }
                    if (Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)) {
                        files.add(entry);
                    } else if (!Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)) {
                        throw new IllegalArgumentException("RUNTIME_ASSET_ENTRY_REJECTED|" + entry);
                    }
                }
            }
        }
        files.sort(Comparator.comparing(path -> normalizedRelativePath(normalizedRoot, path)));

        MessageDigest digest = sha256Digest();
        digest.update(PREPARED_TREE_DOMAIN);
        for (Path file : files) {
            byte[] relative = normalizedRelativePath(normalizedRoot, file)
                    .getBytes(StandardCharsets.UTF_8);
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(relative.length).array());
            digest.update(relative);
            digest.update(ByteBuffer.allocate(Long.BYTES).putLong(Files.size(file)).array());
            try (InputStream input = Files.newInputStream(file)) {
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    if (read > 0) digest.update(buffer, 0, read);
                }
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static Path directPath(String value, String property) {
        Path path = Path.of(value).toAbsolutePath().normalize();
        if (Files.isSymbolicLink(path)) {
            throw new IllegalArgumentException("RUNTIME_ASSET_SYMLINK_REJECTED|" + property + "=" + path);
        }
        return path;
    }

    private static String normalizedRelativePath(Path root, Path path) {
        return root.relativize(path).toString().replace('\\', '/');
    }

    private static String required(Properties properties, String key) {
        String value = properties.getProperty(key, "").trim();
        if (value.isEmpty()) throw new IllegalArgumentException("RUNTIME_PROPERTY_MISSING|" + key);
        return value;
    }

    private static int requiredPositiveInt(Properties properties, String key) {
        String value = required(properties, key);
        try {
            int parsed = Integer.parseInt(value);
            if (parsed <= 0) throw new NumberFormatException("not positive");
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("RUNTIME_PROPERTY_INVALID_INTEGER|" + key + "=" + value,
                    exception);
        }
    }

    private static String normalizeKind(String value, String label) {
        String normalized = Objects.requireNonNull(value, label).trim().toUpperCase(Locale.ROOT);
        if (normalized.isEmpty()) throw new IllegalArgumentException(label + " is blank");
        return normalized;
    }

    private static String normalizeSha256(String value, String label) {
        String normalized = Objects.requireNonNull(value, label).trim().toLowerCase(Locale.ROOT);
        if (!normalized.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("RUNTIME_SHA256_INVALID|" + label);
        }
        return normalized;
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }

    record BackendAssets(
            String backendKind,
            MinecraftWireProfile wireProfile,
            Path backendJar,
            String backendJarSha256,
            Path preparedRoot,
            String preparedRootSha256,
            Path serverJava,
            String serverJavaSha256) {
        BackendAssets {
            backendKind = normalizeKind(backendKind, "backendKind");
            wireProfile = Objects.requireNonNull(wireProfile, "wireProfile");
            backendJar = Objects.requireNonNull(backendJar, "backendJar");
            backendJarSha256 = normalizeSha256(backendJarSha256, "backendJarSha256");
            preparedRoot = Objects.requireNonNull(preparedRoot, "preparedRoot");
            preparedRootSha256 = normalizeSha256(preparedRootSha256, "preparedRootSha256");
            serverJava = Objects.requireNonNull(serverJava, "serverJava");
            serverJavaSha256 = normalizeSha256(serverJavaSha256, "serverJavaSha256");
        }
    }

    private record VerifiedFile(Path path, String sha256) { }

    private record VerifiedDirectory(Path path, String sha256) { }
}
