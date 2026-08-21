package com.ellan.mcace.core.proxy;

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

/** Append-only, content-free authorization journal. Any write failure blocks execution. */
public final class FileTrustedDispositionAuthorizationSink implements TrustedDispositionAuthorizationSink {
    private final Path path;
    private final long maxBytes;

    public FileTrustedDispositionAuthorizationSink(Path path, long maxBytes) throws IOException {
        this.path = Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
        this.maxBytes = maxBytes;
        if (maxBytes <= 0 || maxBytes > 64L * 1024 * 1024) {
            throw new IllegalArgumentException("invalid authorization audit quota");
        }
        Path parent = this.path.getParent();
        if (parent == null) {
            throw new IOException("authorization audit path has no parent");
        }
        Files.createDirectories(parent);
        validateExisting();
    }

    @Override
    public synchronized void append(TrustedDispositionAuthorizationRecord record) throws IOException {
        Objects.requireNonNull(record, "record");
        validateExisting();
        byte[] bytes = (encode(record) + System.lineSeparator()).getBytes(StandardCharsets.UTF_8);
        long size = Files.exists(path, LinkOption.NOFOLLOW_LINKS) ? Files.size(path) : 0L;
        if (size > maxBytes - bytes.length) {
            throw new IOException("authorization audit quota exhausted");
        }
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND, LinkOption.NOFOLLOW_LINKS)) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            channel.force(true);
        }
    }

    private void validateExisting() throws IOException {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        BasicFileAttributes attributes = Files.readAttributes(
                path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (Files.isSymbolicLink(path) || !attributes.isRegularFile() || attributes.size() > maxBytes) {
            throw new IOException("unsafe trusted disposition authorization path");
        }
    }

    private static String encode(TrustedDispositionAuthorizationRecord record) {
        return "v3\t" + record.authorizationId() + "\t" + record.playerId() + "\t"
                + record.authorizedAt().toEpochMilli() + "\t"
                + record.sessionCommitmentSha256() + "\t"
                + record.reviewInputCommitmentSha256() + "\t"
                + record.executionContextCommitmentSha256() + "\t" + record.origin().name() + "\t"
                + record.operatorId().orElse("-") + "\t" + record.reviewTicket().orElse("-") + "\t"
                + record.action().name() + "\t" + record.winningRuleId().orElse("-") + "\t"
                + record.policyStatus().name() + "\t" + record.policyVersion().orElse("-") + "\t"
                + record.policySequence().map(Object::toString).orElse("-") + "\t"
                + record.policyExpiresAt().map(value -> Long.toString(value.toEpochMilli())).orElse("-");
    }
}
