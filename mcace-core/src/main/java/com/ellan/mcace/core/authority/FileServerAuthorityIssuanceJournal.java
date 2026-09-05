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
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Bounded, pre-provisioned Paper/Folia authority-issuance journal.
 *
 * <p>The journal owns one no-follow read/write handle and one exclusive lock for its entire
 * lifetime. On the supported Windows/OpenJDK runtime it additionally disables delete and write
 * sharing, so the named file cannot be replaced or externally written while an issuer is live.
 * Startup decodes the complete bounded journal exactly once into an authenticated in-process
 * recovery index. Each append validates against that index, writes through the same handle, calls
 * {@code force(true)}, and re-reads only the exact appended record before the index is advanced.
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
    private static final String HEADER = "MCACE_SERVER_AUTHORITY_ISSUANCE_JOURNAL_V2";
    private static final byte[] INITIAL_CONTENT = (HEADER + "\n")
            .getBytes(StandardCharsets.US_ASCII);
    private static final String VERSION = "v2";

    private final Path path;
    private final Path canonicalPath;
    private final long maxBytes;
    private final boolean windows;
    private final FileChannel channel;
    private final FileLock fileLock;
    private final List<PathIdentity> identities;
    private final JournalState state;
    private long committedSize;
    private int fullDecodePasses;
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
        AuthorityFilePreflight.requirePrivateRegularFile(
                Objects.requireNonNull(this.path.getParent(), "journal parent"), this.path,
                "authority issuance journal");
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
            byte[] startupBytes = readVerifiedBytes();
            this.state = decode(startupBytes);
            this.committedSize = startupBytes.length;
            this.fullDecodePasses = 1;
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

        try {
            validateSavedIdentity();
            requireExpectedSize();
        } catch (IOException exception) {
            throw poison(exception);
        }

        // A rejected caller record did not mutate storage and therefore does not poison the
        // journal. Storage/identity failures below do.
        state.validate(record);
        byte[] addition = encode(record);
        if (committedSize > maxBytes - addition.length) {
            throw new IOException("authority issuance journal quota exhausted");
        }

        try {
            long appendOffset = committedSize;
            writeAll(channel, appendOffset, addition);
            channel.force(true);
            long expectedSize = Math.addExact(appendOffset, addition.length);
            if (channel.size() != expectedSize) {
                throw new IOException("authority issuance journal changed during forced append");
            }
            byte[] forcedAddition = readExact(channel, appendOffset, addition.length);
            if (!Arrays.equals(addition, forcedAddition)) {
                throw new IOException("authority issuance journal append verification failed");
            }
            validateSavedIdentity();
            if (channel.size() != expectedSize) {
                throw new IOException("authority issuance journal changed after append verification");
            }
            state.commit(record);
            committedSize = expectedSize;
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
            validateSavedIdentity();
            requireExpectedSize();
            return state.lastSequence(lifecycle);
        } catch (IOException exception) {
            throw poison(exception);
        }
    }

    @Override
    synchronized ServerAuthorityIssuanceRecovery recover(String lifecycleCommitmentSha256)
            throws IOException {
        String lifecycle = BackendAuthorityPin.sha256(
                lifecycleCommitmentSha256, "lifecycleCommitmentSha256");
        ensureHealthy();
        try {
            validateSavedIdentity();
            requireExpectedSize();
            return state.recovery(lifecycle);
        } catch (IOException exception) {
            throw poison(exception);
        }
    }

    Path path() {
        return path;
    }

    int fullDecodePassesForTests() {
        return fullDecodePasses;
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

    private void requireExpectedSize() throws IOException {
        if (channel.size() != committedSize) {
            throw new IOException("authority issuance journal size changed outside the writer");
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

    private static byte[] readExact(FileChannel source, long position, int length)
            throws IOException {
        ByteBuffer destination = ByteBuffer.allocate(length);
        long offset = position;
        int zeroReads = 0;
        while (destination.hasRemaining()) {
            int count = source.read(destination, offset);
            if (count < 0) {
                throw new IOException("authority issuance journal append ended early");
            }
            if (count == 0) {
                if (++zeroReads > 8) {
                    throw new IOException("authority issuance journal append verification made no progress");
                }
            } else {
                offset += count;
                zeroReads = 0;
            }
        }
        return destination.array();
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
            state.commit(parse(lines[index]));
        }
        return state;
    }

    private static ServerAuthorityIssuanceRecord parse(String line) throws IOException {
        String[] fields = line.split("\\t", -1);
        if (fields.length != 11 || !VERSION.equals(fields[0])) {
            throw new IOException("invalid authority issuance journal record shape");
        }
        try {
            UUID attestationId = UUID.fromString(fields[1]);
            if (!attestationId.toString().equals(fields[1])) {
                throw new IllegalArgumentException("noncanonical attestation UUID");
            }
            return new ServerAuthorityIssuanceRecord(
                    attestationId, fields[2], Long.parseLong(fields[3]), fields[4], fields[5],
                    fields[6], Instant.ofEpochMilli(Long.parseLong(fields[7])),
                    Instant.ofEpochMilli(Long.parseLong(fields[8])),
                    Instant.ofEpochMilli(Long.parseLong(fields[9])), fields[10]);
        } catch (DateTimeException | IllegalArgumentException exception) {
            throw new IOException("invalid authority issuance journal record", exception);
        }
    }

    private static byte[] encode(ServerAuthorityIssuanceRecord record) {
        String line = VERSION + "\t" + record.attestationId() + "\t"
                + record.backendKeyIdSha256() + "\t" + record.observationSequence() + "\t"
                + record.sessionBindingCommitmentSha256() + "\t"
                + record.authorityProfileSha256() + "\t"
                + record.providerEvidenceCommitmentSha256() + "\t"
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

        void validate(ServerAuthorityIssuanceRecord record) throws IOException {
            if (attestationIds.contains(record.attestationId())) {
                throw new IOException("duplicate authority attestation ID");
            }
            if (signedFrames.contains(record.signedFrameSha256())) {
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
        }

        void commit(ServerAuthorityIssuanceRecord record) throws IOException {
            validate(record);
            attestationIds.add(record.attestationId());
            signedFrames.add(record.signedFrameSha256());
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

        ServerAuthorityIssuanceRecovery recovery(String lifecycleCommitmentSha256) {
            long sequence = lastSequence(lifecycleCommitmentSha256);
            if (sequence == 0L) {
                return ServerAuthorityIssuanceRecovery.empty();
            }
            return new ServerAuthorityIssuanceRecovery(
                    sequence,
                    Optional.of(lastObservedByBinding.get(lifecycleCommitmentSha256)),
                    Optional.of(lastIssuedByBinding.get(lifecycleCommitmentSha256)));
        }
    }
}
