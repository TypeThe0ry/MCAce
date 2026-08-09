package com.ellan.mcace.core.evidence;

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

/** Bounded durable, content-free audit sink for local proxy administration. */
public final class FileEvidenceAuditSink implements EvidenceAuditSink {
    private final Path path;
    private final long maxBytes;

    public FileEvidenceAuditSink(Path path, long maxBytes) throws IOException {
        this.path = Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
        this.maxBytes = maxBytes;
        if (maxBytes <= 0 || maxBytes > 64L * 1024 * 1024) throw new IllegalArgumentException("invalid audit quota");
        Path parent = this.path.getParent();
        if (parent == null) throw new IOException("audit path has no parent");
        Files.createDirectories(parent);
        if (Files.exists(this.path, LinkOption.NOFOLLOW_LINKS)) {
            BasicFileAttributes attrs = Files.readAttributes(this.path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (Files.isSymbolicLink(this.path) || !attrs.isRegularFile()) throw new IOException("unsafe audit path");
        }
    }

    @Override public synchronized void append(EvidenceAuditRecord record) {
        Objects.requireNonNull(record, "record");
        appendLine("COLLECT status=" + record.status() + " evidenceId=" + record.evidenceId()
                + " playerId=" + record.playerId() + " requestId=" + record.requestId()
                + " caseId=" + record.caseId() + " scope=" + record.captureScope()
                + " size=" + record.contentSize() + " operator=" + record.operatorId());
    }

    @Override public synchronized void appendDeletion(EvidenceDeletionAuditRecord record) {
        Objects.requireNonNull(record, "record");
        appendLine("DELETE evidenceId=" + record.evidenceId() + " deleted=" + record.deleted()
                + " operator=" + record.operatorId() + " reason=" + record.reason());
    }

    @Override public synchronized void appendReview(EvidenceReviewAuditRecord record) {
        Objects.requireNonNull(record, "record");
        appendLine("REVIEW outcome=" + record.outcome() + " evidenceId=" + record.evidenceId()
                + " operator=" + record.operatorId() + " reason=" + record.reason());
    }

    private void appendLine(String line) {
        String safe = line.replaceAll("[\\p{Cntrl}\\r\\n]", "?") + System.lineSeparator();
        byte[] bytes = safe.getBytes(StandardCharsets.UTF_8);
        try {
            long current = Files.exists(path, LinkOption.NOFOLLOW_LINKS) ? Files.size(path) : 0L;
            if (current > maxBytes - bytes.length) throw new IllegalStateException("evidence audit quota exceeded");
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND, LinkOption.NOFOLLOW_LINKS)) {
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) channel.write(buffer);
                channel.force(true);
            }
        } catch (IOException exception) {
            throw new IllegalStateException("evidence audit append failed", exception);
        }
    }
}
