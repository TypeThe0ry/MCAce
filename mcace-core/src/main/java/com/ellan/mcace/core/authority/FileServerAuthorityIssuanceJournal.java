package com.ellan.mcace.core.authority;

import com.sun.nio.file.ExtendedOpenOption;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Bounded, pre-provisioned Paper/Folia authority-issuance journal.
 *
 * <p>The journal owns one no-follow read/write handle and one exclusive lock for its entire
 * lifetime. On the supported Windows/OpenJDK runtime it additionally disables delete and write
 * sharing, so the named file cannot be replaced or externally written while an issuer is live.
 * Every append decodes the complete existing journal, writes through that same handle, calls
 * {@code force(true)}, and decodes the complete handle again before a sendable token can escape.
 * It never opens and closes a second channel to the same file while locked: on some POSIX systems
 * doing so releases all process locks for that inode. Path identity is instead checked through
 * no-follow attributes before and after each same-handle read. Windows additionally relies on the
 * lifetime {@code NOSHARE_DELETE}/{@code NOSHARE_WRITE} handle. Any storage or identity fault
 * after construction permanently poisons this instance.</p>
 *
 * <p>The file must already exist with the fixed header. Runtime code never creates the path or
 * its parents because Java cannot portably force a newly-created directory entry on Windows.</p>
 */
final class FileServerAuthorityIssuanceJournal
        extends ServerAuthorityIssuanceJournal implements AutoCloseable {
    static final long MAX_QUOTA_BYTES = 64L * 1024L * 1024L;
    private static final String HEADER = "MCACE_SERVER_AUTHORITY_ISSUANCE_JOURNAL_V1";
    private static final byte[] INITIAL_CONTENT = (HEADER + "\n")
            .getBytes(StandardCharsets.US_ASCII);
    private static final String VERSION = "v1";

    private final Path path;
    private final Path canonicalPath;
    private final long maxBytes;
    private final boolean windows;
    private final FileChannel channel;
    private final FileLock fileLock;
    private final List<PathIdentity> identities;
    private boolean poisoned;
    private boolean closed;

    FileServerAuthorityIssuanceJournal(Path path, long maxBytes) throws IOException {
        this.path = Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
        if (maxBytes < INITIAL_CONTENT.length || maxBytes > MAX_QUOTA_BYTES) {
            throw new IllegalArgumentException("invalid authority issuance journal quota");
        }
        this.maxBytes = maxBytes;
        this.windows = System.getProperty("os.name", "")
                .toLowerCase(Locale.ROOT).startsWith("windows");
        List<PathIdentity> beforeOpen = inspectPathChain(this.path, this.windows, false);
        this.canonicalPath = this.path.toRealPath(LinkOption.NOFOLLOW_LINKS);

        FileChannel opened = null;
        FileLock acquired = null;
        try {
            opened = FileChannel.open(this.path, openOptions(this.windows));
            try {
                acquired = opened.tryLock();
            } catch (OverlappingFileLockException exception) {
                throw new IOException("authority issuance journal is already open", exception);
            }
            if (acquired == null || !acquired.isValid()) {
                throw new IOException("authority issuance journal exclusive lock is unavailable");
            }
            this.channel = opened;
            this.fileLock = acquired;
            this.identities = List.copyOf(beforeOpen);
            verifyIdentityAndReadState();
        } catch (IOException | RuntimeException exception) {
            if (acquired != null) {
                try {
                    acquired.release();
                } catch (IOException releaseFailure) {
                    exception.addSuppressed(releaseFailure);
                }
            }
            if (opened != null) {
                try {
                    opened.close();
                } catch (IOException closeFailure) {
                    exception.addSuppressed(closeFailure);
                }
            }
            if (exception instanceof IOException ioException) {
                throw ioException;
            }
            throw new IOException("authority issuance journal cannot enforce safe access",
                    exception);
        }
    }

    @Override
    synchronized void appendAndForce(ServerAuthorityIssuanceRecord record)
            throws IOException {
        Objects.requireNonNull(record, "record");
        ensureHealthy();

        JournalState state;
        byte[] before;
        try {
            before = readVerifiedBytes();
            state = decode(before);
        } catch (IOException exception) {
            throw poison(exception);
        }

        // A rejected caller record did not mutate storage and therefore does not poison the
        // journal. Storage/identity failures below do.
        state.accept(record);
        byte[] addition = encode(record);
        if (before.length > maxBytes - addition.length) {
            throw new IOException("authority issuance journal quota exhausted");
        }

        try {
            writeAll(channel, before.length, addition);
            channel.force(true);
            long expectedSize = Math.addExact(before.length, addition.length);
            if (channel.size() != expectedSize) {
                throw new IOException("authority issuance journal changed during forced append");
            }
            byte[] after = readVerifiedBytes();
            if (after.length != expectedSize
                    || !Arrays.equals(addition,
                    Arrays.copyOfRange(after, before.length, after.length))) {
                throw new IOException("authority issuance journal append verification failed");
            }
            decode(after);
        } catch (ArithmeticException exception) {
            throw poison(new IOException("authority issuance journal size overflow", exception));
        } catch (IOException exception) {
            throw poison(exception);
        }
    }

    @Override
    synchronized long lastSequence(String lifecycleCommitmentSha256)
            throws IOException {
        String lifecycle = BackendAuthorityPin.sha256(
                lifecycleCommitmentSha256, "lifecycleCommitmentSha256");
        ensureHealthy();
        try {
            return verifyIdentityAndReadState().lastSequence(lifecycle);
        } catch (IOException exception) {
            throw poison(exception);
        }
    }

    Path path() {
        return path;
    }

    static String requiredHeaderLine() {
        return HEADER;
    }

    static byte[] requiredInitialContentUtf8() {
        return INITIAL_CONTENT.clone();
    }

    @Override
    public synchronized void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        IOException failure = null;
        try {
            if (fileLock.isValid()) {
                fileLock.release();
            }
        } catch (IOException exception) {
            failure = exception;
        }
        try {
            channel.close();
        } catch (IOException exception) {
            if (failure == null) {
                failure = exception;
            } else {
                failure.addSuppressed(exception);
            }
        }
        if (failure != null) {
            throw failure;
        }
    }

    private JournalState verifyIdentityAndReadState() throws IOException {
        return decode(readVerifiedBytes());
    }

    private byte[] readVerifiedBytes() throws IOException {
        validateSavedIdentity();
        byte[] handleBytes = readBounded(channel);
        validateSavedIdentity();
        return handleBytes;
    }

    private void validateSavedIdentity() throws IOException {
        if (!canonicalPath.equals(path.toRealPath(LinkOption.NOFOLLOW_LINKS))) {
            throw new IOException("authority issuance journal canonical path changed");
        }
        List<PathIdentity> current = inspectPathChain(path, windows, false);
        if (current.size() != identities.size()) {
            throw new IOException("authority issuance journal path shape changed");
        }
        for (int index = 0; index < identities.size(); index++) {
            PathIdentity expected = identities.get(index);
            PathIdentity observed = current.get(index);
            if (!expected.path().equals(observed.path())
                    || expected.directory() != observed.directory()
                    || (expected.fileKey() != null
                    && !expected.fileKey().equals(observed.fileKey()))) {
                throw new IOException("authority issuance journal path identity changed");
            }
        }
    }

    private byte[] readBounded(FileChannel source) throws IOException {
        long size = source.size();
        if (size < INITIAL_CONTENT.length || size > maxBytes || size > Integer.MAX_VALUE) {
            throw new IOException("authority issuance journal quota or header is invalid");
        }
        ByteBuffer content = ByteBuffer.allocate((int) size);
        source.position(0L);
        while (content.hasRemaining()) {
            int read = source.read(content);
            if (read < 0) {
                throw new IOException("authority issuance journal changed during read");
            }
        }
        if (source.size() != size) {
            throw new IOException("authority issuance journal changed during read");
        }
        return content.array();
    }

    private void ensureHealthy() throws IOException {
        if (closed) {
            throw new IOException("authority issuance journal is closed");
        }
        if (poisoned) {
            throw new IOException("authority issuance journal is poisoned");
        }
        if (!fileLock.isValid() || !channel.isOpen()) {
            poisoned = true;
            throw new IOException("authority issuance journal lock or handle is unavailable");
        }
    }

    private IOException poison(IOException exception) {
        poisoned = true;
        return exception;
    }

    private static Set<OpenOption> openOptions(boolean windows) {
        Set<OpenOption> options = new HashSet<>();
        options.add(StandardOpenOption.READ);
        options.add(StandardOpenOption.WRITE);
        options.add(LinkOption.NOFOLLOW_LINKS);
        if (windows) {
            options.add(ExtendedOpenOption.NOSHARE_DELETE);
            options.add(ExtendedOpenOption.NOSHARE_WRITE);
        }
        return Set.copyOf(options);
    }

    private static List<PathIdentity> inspectPathChain(
            Path leaf, boolean windows, boolean leafIsDirectory)
            throws IOException {
        Path root = leaf.getRoot();
        if (root == null) {
            throw new IOException("authority issuance journal path has no root");
        }
        List<PathIdentity> result = new ArrayList<>();
        Path current = root;
        BasicFileAttributes rootAttributes = attributes(current);
        requireSafeNode(current, rootAttributes, true, windows);
        result.add(new PathIdentity(current, rootAttributes.fileKey(), true));
        for (Path component : leaf) {
            current = current.resolve(component);
            boolean directory = !current.equals(leaf) || leafIsDirectory;
            BasicFileAttributes node = attributes(current);
            requireSafeNode(current, node, directory, windows);
            result.add(new PathIdentity(current, node.fileKey(), directory));
        }
        return result;
    }

    private static BasicFileAttributes attributes(Path node) throws IOException {
        return Files.readAttributes(
                node, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    }

    private static void requireSafeNode(
            Path node, BasicFileAttributes attributes, boolean directory, boolean windows)
            throws IOException {
        if (attributes.isSymbolicLink() || attributes.isOther()
                || (directory && !attributes.isDirectory())
                || (!directory && !attributes.isRegularFile())) {
            throw new IOException("unsafe authority issuance journal path node: "
                    + node.getFileName());
        }
        if (!windows && attributes.fileKey() == null) {
            throw new IOException("authority issuance journal path identity is unavailable");
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "")
                .toLowerCase(Locale.ROOT).startsWith("windows");
    }

    private static void writeAll(FileChannel target, long position, byte[] encoded)
            throws IOException {
        target.position(position);
        ByteBuffer buffer = ByteBuffer.wrap(encoded);
        while (buffer.hasRemaining()) {
            target.write(buffer);
        }
    }

    private static JournalState decode(byte[] encoded) throws IOException {
        String content;
        try {
            content = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(encoded)).toString();
        } catch (CharacterCodingException exception) {
            throw new IOException("authority issuance journal is not valid UTF-8", exception);
        }
        if (!content.endsWith("\n")) {
            throw new IOException("authority issuance journal has a partial record");
        }
        String[] lines = content.split("\n", -1);
        if (lines.length < 2 || !HEADER.equals(lines[0])) {
            throw new IOException("authority issuance journal header is invalid");
        }
        JournalState state = new JournalState();
        for (int index = 1; index < lines.length - 1; index++) {
            if (lines[index].isEmpty()) {
                throw new IOException("authority issuance journal contains an empty record");
            }
            state.accept(parse(lines[index]));
        }
        return state;
    }

    private static ServerAuthorityIssuanceRecord parse(String line) throws IOException {
        String[] fields = line.split("\\t", -1);
        if (fields.length != 10 || !VERSION.equals(fields[0])) {
            throw new IOException("invalid authority issuance journal record shape");
        }
        try {
            UUID attestationId = UUID.fromString(fields[1]);
            if (!attestationId.toString().equals(fields[1])) {
                throw new IllegalArgumentException("noncanonical attestation UUID");
            }
            return new ServerAuthorityIssuanceRecord(
                    attestationId, fields[2], Long.parseLong(fields[3]), fields[4], fields[5],
                    Instant.ofEpochMilli(Long.parseLong(fields[6])),
                    Instant.ofEpochMilli(Long.parseLong(fields[7])),
                    Instant.ofEpochMilli(Long.parseLong(fields[8])), fields[9]);
        } catch (DateTimeException | IllegalArgumentException exception) {
            throw new IOException("invalid authority issuance journal record", exception);
        }
    }

    private static byte[] encode(ServerAuthorityIssuanceRecord record) {
        String line = VERSION + "\t" + record.attestationId() + "\t"
                + record.backendKeyIdSha256() + "\t" + record.observationSequence() + "\t"
                + record.sessionBindingCommitmentSha256() + "\t"
                + record.providerProfileCommitmentSha256() + "\t"
                + record.observedAt().toEpochMilli() + "\t" + record.issuedAt().toEpochMilli()
                + "\t" + record.expiresAt().toEpochMilli() + "\t"
                + record.signedFrameSha256() + "\n";
        return line.getBytes(StandardCharsets.UTF_8);
    }

    private record PathIdentity(Path path, Object fileKey, boolean directory) {
        private PathIdentity {
            Objects.requireNonNull(path, "path");
        }
    }

    private static final class JournalState {
        private final Set<UUID> attestationIds = new HashSet<>();
        private final Set<String> signedFrames = new HashSet<>();
        private final Map<String, Long> lastSequenceByBinding = new HashMap<>();
        private final Map<String, Instant> lastObservedByBinding = new HashMap<>();
        private final Map<String, Instant> lastIssuedByBinding = new HashMap<>();

        void accept(ServerAuthorityIssuanceRecord record) throws IOException {
            if (!attestationIds.add(record.attestationId())) {
                throw new IOException("duplicate authority attestation ID");
            }
            if (!signedFrames.add(record.signedFrameSha256())) {
                throw new IOException("duplicate authority signed frame");
            }
            long previous = lastSequence(record.sessionBindingCommitmentSha256());
            if (record.observationSequence() <= previous) {
                throw new IOException("authority observation sequence did not increase");
            }
            Instant previousObserved = lastObservedByBinding.get(
                    record.sessionBindingCommitmentSha256());
            Instant previousIssued = lastIssuedByBinding.get(
                    record.sessionBindingCommitmentSha256());
            if ((previousObserved != null && record.observedAt().isBefore(previousObserved))
                    || (previousIssued != null && record.issuedAt().isBefore(previousIssued))) {
                throw new IOException("authority issuance time moved backwards for binding");
            }
            lastSequenceByBinding.put(
                    record.sessionBindingCommitmentSha256(), record.observationSequence());
            lastObservedByBinding.put(
                    record.sessionBindingCommitmentSha256(), record.observedAt());
            lastIssuedByBinding.put(
                    record.sessionBindingCommitmentSha256(), record.issuedAt());
        }

        long lastSequence(String lifecycleCommitmentSha256) {
            return lastSequenceByBinding.getOrDefault(lifecycleCommitmentSha256, 0L);
        }
    }
}
