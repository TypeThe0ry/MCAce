package com.ellan.mcace.core.evidence;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.channels.FileChannel;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Objects;
import java.util.Properties;

/** Explicit opt-in storage configuration. Missing consent contract always fails closed to discard. */
public record EvidenceStorageConfiguration(
        boolean enabled, boolean clientConsentContractConfirmed, Path root, Path keyPath,
        long retentionSeconds, String retentionPolicyId, String retentionPurpose,
        long maxBytes, int maxFiles, long maxTotalBytes) {
    public EvidenceStorageConfiguration {
        Objects.requireNonNull(root, "root");
        Objects.requireNonNull(keyPath, "keyPath");
        Objects.requireNonNull(retentionPolicyId, "retentionPolicyId");
        Objects.requireNonNull(retentionPurpose, "retentionPurpose");
        if (enabled && !clientConsentContractConfirmed) {
            throw new IllegalArgumentException("storage requires explicit client consent contract");
        }
        if (enabled) {
            new EvidenceContentStore.RetentionDisclosure(
                    true, retentionSeconds, retentionPolicyId, retentionPurpose);
            if (maxBytes <= 0 || maxFiles <= 0 || maxTotalBytes < maxBytes
                    || maxTotalBytes > EncryptedEvidenceContentStore.MAX_TOTAL_BYTES) {
                throw new IllegalArgumentException("invalid evidence storage quotas");
            }
        }
    }

    public static EvidenceStorageConfiguration disabled(Path root) {
        Path normalized = root.toAbsolutePath().normalize();
        return new EvidenceStorageConfiguration(false, false, normalized,
                normalized.resolveSibling("evidence-storage.key"), 0, "", "", 0, 0, 0);
    }

    public EvidenceStorageRuntime createRuntime(Clock clock, SecureRandom random, EvidenceAuditSink auditSink)
            throws IOException {
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(random, "random");
        Objects.requireNonNull(auditSink, "auditSink");
        if (!enabled) return EvidenceStorageRuntime.disabled(clock, auditSink);
        if (!clientConsentContractConfirmed) return EvidenceStorageRuntime.disabled(clock, auditSink);
        EvidenceContentStore.RetentionDisclosure disclosure =
                new EvidenceContentStore.RetentionDisclosure(true, retentionSeconds, retentionPolicyId, retentionPurpose);
        EncryptedEvidenceContentStore store = new EncryptedEvidenceContentStore(
                root, EvidenceStorageKeyProvider.loadOrCreate(keyPath, random), random, clock,
                disclosure, maxBytes, maxFiles, maxTotalBytes);
        return new EvidenceStorageRuntime(store, new EvidenceAdminService(store, auditSink, clock));
    }

    public static EvidenceStorageConfiguration loadOrCreate(Path configPath, Path defaultRoot) throws IOException {
        Objects.requireNonNull(configPath, "configPath");
        Path path = configPath.toAbsolutePath().normalize();
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)
                && (Files.isSymbolicLink(path)
                || !Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes.class,
                        LinkOption.NOFOLLOW_LINKS).isRegularFile())) {
            throw new IOException("evidence storage config is not a regular file");
        }
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            Path parent = path.getParent();
            if (parent == null) throw new IOException("storage config has no parent");
            Files.createDirectories(parent);
            Properties defaults = new Properties();
            defaults.setProperty("enabled", "false");
            defaults.setProperty("client-consent-contract-confirmed", "false");
            defaults.setProperty("root", defaultRoot.toAbsolutePath().normalize().toString());
            defaults.setProperty("key", parent.resolve("evidence-storage.key").toString());
            defaults.setProperty("retention-seconds", "0");
            defaults.setProperty("retention-policy-id", "");
            defaults.setProperty("retention-purpose", "");
            defaults.setProperty("max-bytes", "16777216");
            defaults.setProperty("max-files", "256");
            defaults.setProperty("max-total-bytes", "268435456");
            try (Writer writer = Files.newBufferedWriter(path, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                defaults.store(writer, "MCAce evidence storage; disabled until an explicit consent contract exists");
            }
        }
        Properties properties = new Properties();
        byte[] configBytes = readBounded(path, 64 * 1024);
        try (Reader reader = new java.io.InputStreamReader(
                new java.io.ByteArrayInputStream(configBytes), StandardCharsets.UTF_8)) { properties.load(reader); }
        java.util.Arrays.fill(configBytes, (byte) 0);
        Path parent = path.getParent();
        Path root = Path.of(properties.getProperty("root", defaultRoot.toString())).toAbsolutePath().normalize();
        Path key = Path.of(properties.getProperty("key", parent.resolve("evidence-storage.key").toString()))
                .toAbsolutePath().normalize();
        boolean enabled = strictBoolean(properties.getProperty("enabled", "false"), "enabled");
        boolean consent = strictBoolean(
                properties.getProperty("client-consent-contract-confirmed", "false"),
                "client-consent-contract-confirmed");
        if (enabled && !consent) {
            throw new IOException("evidence storage opt-in requires client-consent-contract-confirmed=true");
        }
        try {
            return new EvidenceStorageConfiguration(enabled, consent, root, key,
                    Long.parseLong(properties.getProperty("retention-seconds", "0")),
                    properties.getProperty("retention-policy-id", ""),
                    properties.getProperty("retention-purpose", ""),
                    Long.parseLong(properties.getProperty("max-bytes", "16777216")),
                    Integer.parseInt(properties.getProperty("max-files", "256")),
                    Long.parseLong(properties.getProperty("max-total-bytes", "268435456")));
        } catch (NumberFormatException exception) {
            throw new IOException("invalid numeric evidence storage configuration", exception);
        }
    }

    private static boolean strictBoolean(String value, String name) throws IOException {
        if ("true".equalsIgnoreCase(value)) return true;
        if ("false".equalsIgnoreCase(value)) return false;
        throw new IOException("invalid boolean evidence storage setting: " + name);
    }

    private static byte[] readBounded(Path path, int maxBytes) throws IOException {
        long size = Files.size(path);
        if (size < 0 || size > maxBytes) throw new IOException("evidence storage config exceeds bounded size");
        byte[] bytes = new byte[(int) size];
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                int read = channel.read(buffer);
                if (read < 0) throw new IOException("truncated evidence storage config");
            }
        }
        if (Files.size(path) != size) { java.util.Arrays.fill(bytes, (byte) 0); throw new IOException("evidence storage config changed"); }
        return bytes;
    }
}
