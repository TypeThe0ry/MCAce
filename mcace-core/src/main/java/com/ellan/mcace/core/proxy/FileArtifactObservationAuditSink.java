package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.DispositionAction;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/** Bounded durable TSV journal. The format has only fixed summaries and never artifact content. */
public final class FileArtifactObservationAuditSink implements ArtifactObservationAuditSink {
    private static final int MAX_QUERY = 100;
    private final Path path;
    private final long maxBytes;
    private final List<ArtifactObservationAuditRecord> records = new ArrayList<>();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong failures = new AtomicLong();

    public FileArtifactObservationAuditSink(Path path, long maxBytes) throws IOException {
        this.path = Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
        this.maxBytes = maxBytes;
        if (maxBytes <= 0 || maxBytes > 64L * 1024 * 1024) throw new IllegalArgumentException("invalid audit quota");
        Path parent = this.path.getParent();
        if (parent == null) throw new IOException("audit path has no parent");
        Files.createDirectories(parent);
        if (Files.exists(this.path, LinkOption.NOFOLLOW_LINKS)) {
            BasicFileAttributes attributes = Files.readAttributes(this.path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (Files.isSymbolicLink(this.path) || !attributes.isRegularFile() || attributes.size() > maxBytes) {
                throw new IOException("unsafe artifact observation audit path");
            }
            reload();
        }
    }

    @Override public synchronized void append(ArtifactObservationAuditRecord record) {
        Objects.requireNonNull(record, "record");
        String line = encode(record) + System.lineSeparator();
        byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
        try {
            long size = Files.exists(path, LinkOption.NOFOLLOW_LINKS) ? Files.size(path) : 0L;
            if (size > maxBytes - bytes.length) { dropped.incrementAndGet(); return; }
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND, LinkOption.NOFOLLOW_LINKS)) {
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) channel.write(buffer);
                channel.force(true);
            }
            records.add(record);
        } catch (IOException | RuntimeException ignored) { failures.incrementAndGet(); }
    }

    @Override public synchronized ArtifactObservationAuditStatus status() {
        reloadQuietly();
        long bytes;
        try { bytes = Files.exists(path, LinkOption.NOFOLLOW_LINKS) ? Files.size(path) : 0L; }
        catch (IOException ignored) { bytes = 0L; }
        return new ArtifactObservationAuditStatus(true, records.size(), bytes, maxBytes, dropped.get(), failures.get());
    }

    @Override public synchronized List<ArtifactObservationAuditRecord> recent(UUID playerId, int limit) {
        Objects.requireNonNull(playerId, "playerId");
        if (limit <= 0 || limit > MAX_QUERY) throw new IllegalArgumentException("query limit is outside bounds");
        reloadQuietly();
        List<ArtifactObservationAuditRecord> result = new ArrayList<>();
        for (int index = records.size() - 1; index >= 0 && result.size() < limit; index--) {
            ArtifactObservationAuditRecord record = records.get(index);
            if (record.playerId().equals(playerId)) result.add(record);
        }
        return List.copyOf(result);
    }

    private void reloadQuietly() { try { reload(); } catch (IOException ignored) { failures.incrementAndGet(); } }
    private void reload() throws IOException {
        records.clear();
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return;
        if (Files.isSymbolicLink(path) || Files.size(path) > maxBytes) throw new IOException("unsafe artifact observation audit journal");
        for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) parse(line).ifPresent(records::add);
    }

    private static String encode(ArtifactObservationAuditRecord record) {
        StringBuilder actions = new StringBuilder();
        for (DispositionAction action : DispositionAction.values()) {
            if (actions.length() > 0) actions.append(',');
            actions.append(action.name()).append('=').append(record.actionCounts().getOrDefault(action, 0));
        }
        return record.playerId() + "\t" + record.observedAt().toEpochMilli()
                + "\t" + record.evaluatedAt().toEpochMilli() + "\t" + record.observationCount() + "\t"
                + record.consistencyIssueCount() + "\t" + record.policyStatus().name() + "\t" + actions;
    }

    private static java.util.Optional<ArtifactObservationAuditRecord> parse(String line) {
        try {
            String[] fields = line.split("\\t", -1);
            if (fields.length != 7) return java.util.Optional.empty();
            EnumMap<DispositionAction, Integer> actions = new EnumMap<>(DispositionAction.class);
            for (String item : fields[6].split(",", -1)) {
                String[] pair = item.split("=", -1);
                if (pair.length != 2) return java.util.Optional.empty();
                actions.put(DispositionAction.valueOf(pair[0]), Integer.parseInt(pair[1]));
            }
            return java.util.Optional.of(new ArtifactObservationAuditRecord(UUID.fromString(fields[0]),
                    Instant.ofEpochMilli(Long.parseLong(fields[1])), Instant.ofEpochMilli(Long.parseLong(fields[2])),
                    Integer.parseInt(fields[3]), Integer.parseInt(fields[4]), actions,
                    ProxyPolicyRefreshStatus.valueOf(fields[5])));
        } catch (RuntimeException ignored) { return java.util.Optional.empty(); }
    }
}
