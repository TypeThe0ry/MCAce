package com.ellan.mcace.core.evidence;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;

/** Strict opt-in configuration for the local evidence-review endpoint. */
public record EvidenceReviewEndpointConfiguration(
        boolean enabled, String bindAddress, int port, int tokenTtlSeconds, int maxTokens) {
    public static final String FILE_NAME = "evidence-review.properties";
    private static final String DEFAULT_CONTENT = """
            # Local evidence review is disabled by default. It never binds beyond loopback.
            enabled=false
            bind=127.0.0.1
            # 0 selects an ephemeral loopback port when review is explicitly enabled.
            port=0
            token-ttl-seconds=60
            max-tokens=16
            """;

    public EvidenceReviewEndpointConfiguration {
        Objects.requireNonNull(bindAddress, "bindAddress");
        if (!"127.0.0.1".equals(bindAddress)
                || port < 0 || port > 65_535
                || tokenTtlSeconds < 10 || tokenTtlSeconds > 300
                || maxTokens < 1 || maxTokens > 128) {
            throw new IllegalArgumentException("invalid local evidence-review configuration");
        }
    }

    public static EvidenceReviewEndpointConfiguration loadOrCreate(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        Path normalized = path.toAbsolutePath().normalize();
        if (Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)
                && (Files.isSymbolicLink(normalized)
                || !Files.readAttributes(normalized, java.nio.file.attribute.BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS).isRegularFile())) {
            throw new IOException("evidence review config is not a regular file");
        }
        if (!Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)) {
            Path parent = Objects.requireNonNull(normalized.getParent(), "configuration parent");
            Files.createDirectories(parent);
            try (Writer writer = Files.newBufferedWriter(normalized, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                writer.write(DEFAULT_CONTENT);
            }
        }
        byte[] configBytes = readBounded(normalized, 64 * 1024);
        Properties properties = new Properties();
        try (Reader reader = new java.io.InputStreamReader(
                new java.io.ByteArrayInputStream(configBytes), StandardCharsets.UTF_8)) {
            validatePropertyShape(configBytes);
            properties.load(reader);
        } finally {
            java.util.Arrays.fill(configBytes, (byte) 0);
        }
        try {
            return new EvidenceReviewEndpointConfiguration(
                    strictBoolean(properties.getProperty("enabled", "false"), "enabled"),
                    properties.getProperty("bind", "127.0.0.1").trim(),
                    Integer.parseInt(properties.getProperty("port", "0").trim()),
                    Integer.parseInt(properties.getProperty("token-ttl-seconds", "60").trim()),
                    Integer.parseInt(properties.getProperty("max-tokens", "16").trim()));
        } catch (IllegalArgumentException exception) {
            throw new IOException("invalid evidence review configuration", exception);
        }
    }

    private static boolean strictBoolean(String value, String name) throws IOException {
        if ("true".equalsIgnoreCase(value.trim())) return true;
        if ("false".equalsIgnoreCase(value.trim())) return false;
        throw new IOException("invalid evidence review setting: " + name);
    }

    /**
     * Keep this local-facing security configuration deliberately smaller than general Java
     * properties: no unknown or repeated keys, continuations, or escaped keys. This prevents a
     * later edit from silently changing which value wins.
     */
    private static void validatePropertyShape(byte[] bytes) throws IOException {
        Set<String> allowed = Set.of("enabled", "bind", "port", "token-ttl-seconds", "max-tokens");
        Set<String> seen = new java.util.HashSet<>();
        String text = new String(bytes, StandardCharsets.UTF_8);
        for (String rawLine : text.split("\\R", -1)) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) {
                continue;
            }
            int separator = line.indexOf('=');
            if (separator <= 0 || line.indexOf('\\') >= 0) {
                throw new IOException("invalid evidence review configuration syntax");
            }
            String key = line.substring(0, separator).trim();
            if (!allowed.contains(key) || !seen.add(key)) {
                throw new IOException("unknown or duplicate evidence review configuration key");
            }
        }
    }

    private static byte[] readBounded(Path path, int maxBytes) throws IOException {
        long size = Files.size(path);
        if (size < 0 || size > maxBytes) {
            throw new IOException("evidence review config exceeds bounded size");
        }
        byte[] bytes = new byte[(int) size];
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                int read = channel.read(buffer);
                if (read < 0) {
                    throw new IOException("truncated evidence review config");
                }
            }
        }
        if (Files.size(path) != size) {
            java.util.Arrays.fill(bytes, (byte) 0);
            throw new IOException("evidence review config changed while reading");
        }
        return bytes;
    }
}
