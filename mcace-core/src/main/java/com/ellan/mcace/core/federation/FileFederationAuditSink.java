package com.ellan.mcace.core.federation;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;
import java.util.UUID;

/** Bounded, durable, append-only local journal containing only {@link FederationAuditRecord}. */
public final class FileFederationAuditSink implements FederationAuditSink {
    private final Path path;
    private final long maxBytes;

    public FileFederationAuditSink(Path path, long maxBytes) throws IOException {
        this.path = Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
        this.maxBytes = maxBytes;
        if (maxBytes <= 0L || maxBytes > 64L * 1024L * 1024L) {
            throw new IllegalArgumentException("invalid federation audit quota");
        }
        Path parent = this.path.getParent();
        if (parent == null) {
            throw new IOException("federation audit path has no parent");
        }
        Files.createDirectories(parent);
        if (Files.exists(this.path, LinkOption.NOFOLLOW_LINKS)) {
            BasicFileAttributes attributes = Files.readAttributes(
                    this.path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (Files.isSymbolicLink(this.path) || !attributes.isRegularFile() || attributes.size() > maxBytes) {
                throw new IOException("unsafe federation audit path");
            }
        }
    }

    @Override
    public synchronized void append(FederationAuditRecord record) {
        Objects.requireNonNull(record, "record");
        String line = record.recordedAt().toEpochMilli()
                + "\t" + record.event().name()
                + "\t" + record.outcome().name()
                + "\t" + record.operatorId()
                + "\t" + record.playerId()
                + "\t" + record.sourceNetworkId()
                + "\t" + record.targetNetworkId()
                + "\t" + record.assertionId().map(UUID::toString).orElse("")
                + "\t" + record.peerKeyFingerprint().orElse("")
                + System.lineSeparator();
        byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
        try {
            if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)
                    && (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))) {
                throw new IOException("unsafe federation audit path");
            }
            long current = Files.exists(path, LinkOption.NOFOLLOW_LINKS) ? Files.size(path) : 0L;
            if (current > maxBytes - bytes.length) {
                throw new IOException("federation audit quota exceeded");
            }
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE, StandardOpenOption.APPEND, LinkOption.NOFOLLOW_LINKS)) {
                long openedSize = channel.size();
                if (openedSize != current || openedSize > maxBytes - bytes.length) {
                    throw new IOException("federation audit changed or exceeded its quota");
                }
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
        } catch (IOException exception) {
            throw new IllegalStateException("federation audit append failed", exception);
        }
    }
}
