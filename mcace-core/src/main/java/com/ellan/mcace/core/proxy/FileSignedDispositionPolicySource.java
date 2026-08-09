package com.ellan.mcace.core.proxy;

import com.ellan.mcace.protocol.generated.DispositionPolicyDocument;
import com.ellan.mcace.protocol.generated.SignedDispositionPolicyDocument;
import com.ellan.mcace.protocol.policy.DispositionPolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyException;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Local, platform-neutral source for a root-signed disposition policy document.
 *
 * <p>This class deliberately has a small authority boundary.  It only creates the first
 * bootstrap document; subsequently it reads the exact bytes provided by an operator or a policy
 * distributor.  Invalid, oversized, substituted, or expired documents are never repaired or
 * overwritten here.  The shared proxy runtime additionally evaluates freshness and chaining.
 */
public final class FileSignedDispositionPolicySource implements SignedDispositionPolicySource {
    /** Upper bound for one protobuf wrapper, including the signed policy bytes. */
    public static final int DEFAULT_MAX_DOCUMENT_BYTES = 1_048_576;

    private static final Duration BOOTSTRAP_LIFETIME = Duration.ofHours(24);
    private static final int READ_BUFFER_BYTES = 8_192;
    private static final String BOOTSTRAP_POLICY_ID = "mcace-default-observe";
    private static final String BOOTSTRAP_VERSION = "bootstrap-1";
    // Coordinates independently constructed sources in one proxy JVM. The filesystem move remains
    // the cross-process boundary; the lock prevents two plugin components in one JVM racing it.
    private static final ConcurrentHashMap<Path, Object> CREATION_LOCKS = new ConcurrentHashMap<>();

    static Object pathLock(Path path) {
        return CREATION_LOCKS.computeIfAbsent(path, ignored -> new Object());
    }

    private final Path path;
    private final Clock clock;
    private final KeyPair signingKeyPair;
    private final byte[] signerKeyId;
    private final int maxDocumentBytes;
    private String lastFingerprint;

    /**
     * Creates a source without reading, parsing, or creating a file.  This keeps plugin startup
     * non-fatal: a malformed existing file becomes an OBSERVE fallback when {@link #current()} is
     * called by {@link SharedProxyDispositionPolicyRuntime}.
     */
    public FileSignedDispositionPolicySource(Path policyPath, Clock clock, KeyPair signingKeyPair)
            throws PolicyException {
        this(policyPath, clock, signingKeyPair, DEFAULT_MAX_DOCUMENT_BYTES);
    }

    /** Visible for bounded-I/O tests and integrations with a stricter storage budget. */
    public FileSignedDispositionPolicySource(
            Path policyPath, Clock clock, KeyPair signingKeyPair, int maxDocumentBytes)
            throws PolicyException {
        Objects.requireNonNull(policyPath, "policyPath");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.signingKeyPair = Objects.requireNonNull(signingKeyPair, "signingKeyPair");
        Objects.requireNonNull(signingKeyPair.getPrivate(), "signingKeyPair.private");
        Objects.requireNonNull(signingKeyPair.getPublic(), "signingKeyPair.public");
        if (maxDocumentBytes < 256) {
            throw new IllegalArgumentException("maxDocumentBytes must be at least 256");
        }
        if (!policyPath.isAbsolute() || !policyPath.equals(policyPath.normalize())
                || policyPath.getFileName() == null) {
            throw new IllegalArgumentException("policyPath must be an absolute normalized file path");
        }
        this.path = policyPath;
        this.maxDocumentBytes = maxDocumentBytes;
        this.signerKeyId = PolicyDocuments.keyId(signingKeyPair.getPublic());
    }

    /** The exact, absolute, normalized policy path this source is allowed to access. */
    public Path path() {
        return path;
    }

    /** The bounded maximum serialized wrapper size accepted from disk. */
    public int maxDocumentBytes() {
        return maxDocumentBytes;
    }

    /**
     * SHA-256 fingerprint of the exact current on-disk signed wrapper.  This refreshes the source
     * first, therefore it never reports a fingerprint for an unparseable or untrusted document.
     */
    public String fingerprint() throws PolicyException {
        synchronized (pathLock(path)) {
            currentLocked();
            return lastFingerprint;
        }
    }

    /**
     * Reads the existing document unchanged, or atomically creates a signed, zero-rule OBSERVE
     * bootstrap document if and only if the configured path does not exist.
     */
    @Override
    public SignedDispositionPolicyDocument current() throws PolicyException {
        synchronized (pathLock(path)) {
            return currentLocked();
        }
    }

    /** Caller must hold the single shared lock for this exact normalized path. */
    private SignedDispositionPolicyDocument currentLocked() throws PolicyException {
        if (existsNoFollow(path)) {
            return readExisting();
        }
        if (!Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new PolicyException("cannot determine disposition policy file state: " + path);
        }
        createBootstrapIfAbsent();
        return readExisting();
    }

    private SignedDispositionPolicyDocument readExisting() throws PolicyException {
        byte[] bytes = readBoundedRegularFile();
        SignedDispositionPolicyDocument signed;
        try {
            signed = SignedDispositionPolicyDocument.parseFrom(bytes);
        } catch (InvalidProtocolBufferException exception) {
            throw new PolicyException("cannot parse disposition policy file: " + path, exception);
        }
        // A source key mismatch or malformed signed wrapper is an operator-visible failure, never
        // a reason to silently sign a replacement. Freshness intentionally remains the runtime's
        // responsibility so it can downgrade an expired policy to OBSERVE with a useful status.
        DispositionPolicyDocuments.verifySignatureAndStructure(signed, signingKeyPair.getPublic());
        lastFingerprint = sha256Hex(bytes);
        return signed;
    }

    private byte[] readBoundedRegularFile() throws PolicyException {
        try {
            BasicFileAttributes attributes = Files.readAttributes(
                    path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (attributes.isSymbolicLink() || !attributes.isRegularFile()) {
                throw new PolicyException("disposition policy path is not a regular file: " + path);
            }
            if (attributes.size() > maxDocumentBytes) {
                throw new PolicyException("disposition policy file exceeds " + maxDocumentBytes + " bytes: " + path);
            }
            // The size check above only provides an early rejection.  Read through a fixed-size
            // buffer as the authoritative bound because another process may grow the file after
            // stat(); readAllBytes would allocate before it could enforce that second boundary.
            try (SeekableByteChannel channel = Files.newByteChannel(
                    path, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));
                    ByteArrayOutputStream output = new ByteArrayOutputStream((int) attributes.size())) {
                java.nio.ByteBuffer buffer = java.nio.ByteBuffer.allocate(READ_BUFFER_BYTES);
                int total = 0;
                while (channel.read(buffer) != -1) {
                    int read = buffer.position();
                    if (read == 0) {
                        continue;
                    }
                    if (read > maxDocumentBytes - total) {
                        throw new PolicyException("disposition policy file grew beyond its read budget: " + path);
                    }
                    output.write(buffer.array(), 0, read);
                    total += read;
                    buffer.clear();
                }
                return output.toByteArray();
            }
        } catch (IOException exception) {
            throw new PolicyException("cannot read disposition policy file: " + path, exception);
        }
    }

    private void createBootstrapIfAbsent() throws PolicyException {
        Path parent = path.getParent();
        ensureSafeParent(parent);
        SignedDispositionPolicyDocument bootstrap = bootstrapDocument();
        byte[] bytes = bootstrap.toByteArray();
        if (bytes.length > maxDocumentBytes) {
            throw new PolicyException("bootstrap disposition policy exceeds storage budget");
        }

        Path temporary = null;
        try {
            temporary = Files.createTempFile(parent, "." + path.getFileName() + ".", ".tmp");
            writeAndForce(temporary, bytes);
            try {
                // No REPLACE_EXISTING is supplied.  A competing creator must win unchanged.
                Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException exception) {
                // Windows and some filesystems do not support atomic moves. The temporary file is
                // still fully forced before this non-replacing same-directory fallback move.
                Files.move(temporary, path);
            }
        } catch (java.nio.file.FileAlreadyExistsException exception) {
            // Another process initialized this exact path. Its bytes are read and verified below.
        } catch (IOException exception) {
            throw new PolicyException("cannot create bootstrap disposition policy: " + path, exception);
        } finally {
            if (temporary != null) {
                try {
                    Files.deleteIfExists(temporary);
                } catch (IOException ignored) {
                    // A failed cleanup cannot change the policy and must not mask a write error.
                }
            }
        }
    }

    private SignedDispositionPolicyDocument bootstrapDocument() throws PolicyException {
        long issuedAt = clock.millis();
        long expiresAt;
        try {
            expiresAt = Math.addExact(issuedAt, BOOTSTRAP_LIFETIME.toMillis());
        } catch (ArithmeticException exception) {
            throw new PolicyException("bootstrap policy clock overflow", exception);
        }
        DispositionPolicyDocument document = DispositionPolicyDocument.newBuilder()
                .setSchemaVersion(1)
                .setPolicyId(BOOTSTRAP_POLICY_ID)
                .setVersion(BOOTSTRAP_VERSION)
                .setSequence(1)
                .setIssuedAtEpochMs(issuedAt)
                .setEffectiveFromEpochMs(issuedAt)
                .setExpiresAtEpochMs(expiresAt)
                .setRolloutStage("OBSERVE")
                .setSignerKeyIdSha256(ByteString.copyFrom(signerKeyId))
                .build();
        return DispositionPolicyDocuments.sign(
                document, signingKeyPair.getPrivate(), signingKeyPair.getPublic());
    }

    private static void writeAndForce(Path temporary, byte[] bytes) throws IOException {
        try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
            java.nio.ByteBuffer buffer = java.nio.ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                if (channel.write(buffer) == 0) {
                    throw new IOException("failed to make progress writing disposition policy");
                }
            }
            channel.force(true);
        }
    }

    private static void ensureSafeParent(Path parent) throws PolicyException {
        try {
            if (!Files.exists(parent, LinkOption.NOFOLLOW_LINKS)) {
                Files.createDirectories(parent);
            }
            BasicFileAttributes attributes = Files.readAttributes(
                    parent, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (attributes.isSymbolicLink() || !attributes.isDirectory()) {
                throw new PolicyException("disposition policy parent is not a directory: " + parent);
            }
        } catch (IOException exception) {
            throw new PolicyException("cannot create disposition policy directory: " + parent, exception);
        }
    }

    private static boolean existsNoFollow(Path candidate) throws PolicyException {
        try {
            return Files.exists(candidate, LinkOption.NOFOLLOW_LINKS);
        } catch (SecurityException exception) {
            throw new PolicyException("cannot inspect disposition policy path: " + candidate, exception);
        }
    }

    private static String sha256Hex(byte[] value) throws PolicyException {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new PolicyException("SHA-256 is unavailable", exception);
        }
    }
}
