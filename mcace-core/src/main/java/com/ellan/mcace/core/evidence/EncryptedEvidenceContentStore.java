package com.ellan.mcace.core.evidence;

import com.ellan.mcace.protocol.ProtocolConstants;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Bounded AES-256-GCM evidence store. The key is supplied independently of the server identity
 * key; this class never accepts or derives an Ed25519 key.
 */
public final class EncryptedEvidenceContentStore implements EvidenceContentStore, EvidenceStoreControl, EvidenceReviewReader {
    private static final int MAGIC = 0x4D434553; // MCES
    private static final int VERSION_V1 = 1;
    private static final int VERSION_V2 = 2;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BYTES = 16;
    private static final int HEADER_CIPHERTEXT_BYTES = Long.BYTES + TAG_BYTES;
    private static final int HEADER_BYTES = 4 + 1 + NONCE_BYTES + HEADER_CIPHERTEXT_BYTES + NONCE_BYTES;
    private static final int MAX_REASONABLE_PATH_FILES = 65_536;
    public static final long MAX_TOTAL_BYTES = 1L * 1024 * 1024 * 1024;

    private final Path root;
    private final SecretKey key;
    private final SecureRandom random;
    private final Clock clock;
    private final RetentionDisclosure disclosure;
    private final long maxBytes;
    private final int maxFiles;
    private final long maxTotalBytes;

    public EncryptedEvidenceContentStore(
            Path root, SecretKey key, SecureRandom random, Clock clock,
            RetentionDisclosure disclosure, long maxBytes, int maxFiles, long maxTotalBytes) throws IOException {
        this.root = safeRoot(root);
        this.key = validateKey(key);
        this.random = Objects.requireNonNull(random, "random");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.disclosure = Objects.requireNonNull(disclosure, "disclosure");
        if (!disclosure.rawContentRetained() || disclosure.retentionSeconds() > ProtocolConstants.MAX_EVIDENCE_RETENTION_SECONDS
                || maxBytes <= 0 || maxBytes > ProtocolConstants.MAX_EVIDENCE_TOTAL_BYTES
                || maxFiles <= 0 || maxFiles > MAX_REASONABLE_PATH_FILES || maxTotalBytes < maxBytes
                || maxTotalBytes > MAX_TOTAL_BYTES) {
            throw new IllegalArgumentException("invalid bounded evidence storage policy");
        }
        this.maxBytes = maxBytes;
        this.maxFiles = maxFiles;
        this.maxTotalBytes = maxTotalBytes;
    }

    @Override public RetentionDisclosure retentionDisclosure() { return disclosure; }

    @Override
    public synchronized StoreResult store(EvidenceContent content, EvidenceStorageMetadata metadata) throws Exception {
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(metadata, "metadata");
        if (!content.evidenceId().equals(metadata.evidenceId()) || !content.playerId().equals(metadata.playerId())
                || !content.sessionId().equals(metadata.sessionId()) || !content.requestId().equals(metadata.requestId())
                || !java.security.MessageDigest.isEqual(content.contentSha256(), metadata.contentSha256())
                || !java.security.MessageDigest.isEqual(sha256(content.content()), content.contentSha256())
                || metadata.retentionSeconds() != disclosure.retentionSeconds()
                || !metadata.retentionPolicyId().equals(disclosure.retentionPolicyId())
                || !metadata.retentionPurpose().equals(disclosure.retentionPurpose())
                || metadata.type() == com.ellan.mcace.protocol.generated.EvidenceType.EVIDENCE_UNSPECIFIED
                || metadata.captureScope() == com.ellan.mcace.protocol.generated.EvidenceCaptureScope.EVIDENCE_CAPTURE_SCOPE_UNSPECIFIED
                || metadata.status() == com.ellan.mcace.protocol.generated.EvidenceCollectionStatus.EVIDENCE_COLLECTION_STATUS_UNSPECIFIED) {
            throw new EvidenceStorageException("evidence metadata binding failed");
        }
        byte[] plain = content.content();
        if (plain.length == 0 || plain.length > maxBytes) {
            throw new EvidenceStorageException("evidence input exceeds storage bound");
        }
        Path target = target(content.evidenceId());
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new EvidenceStorageException("evidence id already exists");
        }
        Inventory inventory;
        try {
            inventory = inventory();
        } catch (ArithmeticException overflow) {
            throw new EvidenceStorageException("evidence quota accounting overflow", overflow);
        }
        final long expiresAt;
        try {
            expiresAt = Math.addExact(clock.millis(), Math.multiplyExact(disclosure.retentionSeconds(), 1000L));
        } catch (ArithmeticException overflow) {
            throw new EvidenceStorageException("evidence retention accounting overflow", overflow);
        }
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        byte[] encryptedPlain = serializeV2(metadata, plain);
        byte[] ciphertext;
        try { ciphertext = encrypt(encryptedPlain, nonce, v2Aad(content.evidenceId(), expiresAt)); }
        finally { java.util.Arrays.fill(encryptedPlain, (byte) 0); }
        long fileBytes = HEADER_BYTES + ciphertext.length;
        if (inventory.fileCount >= maxFiles || inventory.totalBytes > maxTotalBytes - fileBytes) {
            throw new EvidenceStorageException("evidence storage quota exceeded");
        }
        byte[] envelope = encode(content.evidenceId(), expiresAt, nonce, ciphertext, VERSION_V2);
        Path temporary = root.resolve("." + content.evidenceId() + ".tmp").normalize();
        if (!temporary.startsWith(root)) throw new EvidenceStorageException("unsafe evidence path");
        try {
            try (FileChannel channel = FileChannel.open(
                    temporary, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS)) {
                ByteBuffer buffer = ByteBuffer.wrap(envelope);
                while (buffer.hasRemaining()) channel.write(buffer);
                channel.force(true);
            }
            moveAtomically(temporary, target);
        } catch (Exception exception) {
            Files.deleteIfExists(temporary);
            throw exception;
        }
        return new StoreResult("evidence://encrypted/" + content.evidenceId());
    }

    @Override
    public StoreResult store(EvidenceContent content) throws Exception {
        throw new EvidenceStorageException("full evidence metadata is required for encrypted storage");
    }

    /** Bounded decrypt; authentication failure returns no plaintext. */
    public synchronized byte[] read(UUID evidenceId, EvidenceStorageMetadata metadata) throws Exception {
        Objects.requireNonNull(evidenceId, "evidenceId");
        Objects.requireNonNull(metadata, "metadata");
        if (!evidenceId.equals(metadata.evidenceId())) throw new EvidenceStorageException("evidence id mismatch");
        Path path = target(evidenceId);
        validateRegular(path);
        long size = Files.size(path);
        if (size < HEADER_BYTES + TAG_BYTES || size > HEADER_BYTES + maxBytes + 4096L + TAG_BYTES) {
            throw new EvidenceStorageException("stored evidence envelope exceeds bound");
        }
        byte[] encoded = readBounded(path, (int) size);
        if (Files.size(path) != size) throw new EvidenceStorageException("stored evidence changed during read");
        Envelope envelope = decode(encoded, evidenceId);
        if (envelope.expiresAtEpochMs <= clock.millis()) {
            throw new EvidenceStorageException("evidence retention has expired");
        }
        byte[] plain;
        if (envelope.version == VERSION_V1) plain = decrypt(envelope.nonce, envelope.ciphertext, metadata.aad());
        else {
            ReviewPlain review = decryptV2(envelope, evidenceId);
            if (!java.security.MessageDigest.isEqual(review.metadata.aad(), metadata.aad())) {
                java.util.Arrays.fill(review.content, (byte) 0);
                throw new EvidenceStorageException("stored evidence metadata does not match review request");
            }
            plain = review.content;
        }
        if (plain.length == 0 || plain.length > maxBytes
                || !java.security.MessageDigest.isEqual(sha256(plain), metadata.contentSha256())) {
            java.util.Arrays.fill(plain, (byte) 0);
            throw new EvidenceStorageException("stored evidence integrity failed");
        }
        return plain;
    }

    /** Only v2 records are self-describing enough for review. v1 remains legacy read(metadata) only. */
    @Override public synchronized java.util.Optional<EvidenceReviewArtifact> readForReview(UUID evidenceId) throws Exception {
        Objects.requireNonNull(evidenceId, "evidenceId");
        Path path = target(evidenceId);
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return java.util.Optional.empty();
        validateRegular(path);
        long size = Files.size(path);
        if (size < HEADER_BYTES + TAG_BYTES || size > HEADER_BYTES + maxBytes + 4096L + TAG_BYTES) {
            throw new EvidenceStorageException("stored evidence envelope exceeds review bound");
        }
        byte[] encoded = readBounded(path, Math.toIntExact(size));
        if (Files.size(path) != size) throw new EvidenceStorageException("stored evidence changed during read");
        Envelope envelope = decode(encoded, evidenceId);
        if (envelope.version != VERSION_V2) return java.util.Optional.empty();
        if (envelope.expiresAtEpochMs <= clock.millis()) throw new EvidenceStorageException("evidence retention has expired");
        ReviewPlain review = decryptV2(envelope, evidenceId);
        if (!review.metadata.evidenceId().equals(evidenceId) || review.content.length == 0 || review.content.length > maxBytes
                || !java.security.MessageDigest.isEqual(sha256(review.content), review.metadata.contentSha256())) {
            java.util.Arrays.fill(review.content, (byte) 0);
            throw new EvidenceStorageException("stored review evidence integrity failed");
        }
        try {
            return java.util.Optional.of(new EvidenceReviewArtifact(review.metadata,
                    java.time.Instant.ofEpochMilli(envelope.expiresAtEpochMs), review.content));
        } finally {
            // EvidenceReviewArtifact owns a defensive copy; do not retain the decrypted staging buffer.
            java.util.Arrays.fill(review.content, (byte) 0);
        }
    }

    @Override public synchronized EvidenceStoreStatus status() {
        try {
            Inventory inventory = inventory();
            return new EvidenceStoreStatus(true, "ENABLED", inventory.fileCount, inventory.totalBytes,
                    maxFiles, maxTotalBytes, disclosure.retentionSeconds(), disclosure.retentionPolicyId());
        } catch (Exception exception) {
            return new EvidenceStoreStatus(false, "FAILED_CLOSED", 0, 0,
                    maxFiles, maxTotalBytes, disclosure.retentionSeconds(), disclosure.retentionPolicyId());
        }
    }

    @Override public synchronized boolean delete(UUID evidenceId) throws IOException {
        Path path = target(Objects.requireNonNull(evidenceId, "evidenceId"));
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return false;
        validateRegular(path);
        Files.delete(path);
        return true;
    }

    @Override public synchronized int sweepExpired(int maxDeletes) throws IOException {
        if (maxDeletes <= 0 || maxDeletes > maxFiles) throw new IllegalArgumentException("invalid sweep bound");
        int deleted = 0;
        for (Path path : boundedFiles()) {
            if (deleted >= maxDeletes) break;
            validateRegular(path);
            long expiresAt = decodeHeader(path);
            if (expiresAt <= clock.millis()) {
                Files.delete(path);
                deleted++;
            }
        }
        return deleted;
    }

    private Inventory inventory() throws IOException {
        long count = 0;
        long bytes = 0;
        for (Path path : boundedFiles()) {
            validateRegular(path);
            count++;
            bytes = Math.addExact(bytes, Files.size(path));
        }
        return new Inventory(count, bytes);
    }

    private List<Path> boundedFiles() throws IOException {
        List<Path> files = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(root, "*.mce")) {
            for (Path path : stream) {
                if (files.size() >= maxFiles + 1) throw new IOException("evidence file count exceeds bound");
                files.add(path.toAbsolutePath().normalize());
            }
        }
        return files;
    }

    private Path target(UUID evidenceId) throws IOException {
        Path path = root.resolve(evidenceId.toString() + ".mce").normalize();
        if (!path.startsWith(root) || !path.getFileName().toString().matches("[0-9a-fA-F-]{36}\\.mce")) {
            throw new IOException("unsafe evidence path");
        }
        return path;
    }

    private static Path safeRoot(Path value) throws IOException {
        Path root = Objects.requireNonNull(value, "root").toAbsolutePath().normalize();
        Files.createDirectories(root);
        BasicFileAttributes attrs = Files.readAttributes(root, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attrs.isDirectory() || Files.isSymbolicLink(root)) throw new IOException("evidence root is not safe");
        return root.toRealPath(LinkOption.NOFOLLOW_LINKS);
    }

    private static SecretKey validateKey(SecretKey key) {
        Objects.requireNonNull(key, "key");
        byte[] encoded = key.getEncoded();
        if (!"AES".equalsIgnoreCase(key.getAlgorithm()) || encoded == null || encoded.length != 32) {
            throw new IllegalArgumentException("evidence storage requires an independent AES-256 key");
        }
        return new SecretKeySpec(encoded.clone(), "AES");
    }

    private void validateRegular(Path path) throws IOException {
        BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attrs.isRegularFile() || Files.isSymbolicLink(path)) throw new IOException("evidence file is not safe");
    }

    private void moveAtomically(Path temporary, Path target) throws IOException {
        try { Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE); }
        catch (AtomicMoveNotSupportedException exception) {
            throw new IOException("atomic evidence move is unavailable", exception);
        }
    }

    private byte[] encrypt(byte[] plain, byte[] nonce, byte[] aad) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(plain);
    }

    private byte[] decrypt(byte[] nonce, byte[] ciphertext, byte[] aad) throws IOException {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException exception) {
            throw new EvidenceStorageException("evidence authentication failed", exception);
        }
    }

    private byte[] encode(UUID evidenceId, long expiresAt, byte[] nonce, byte[] ciphertext, int version) throws Exception {
        byte[] headerNonce = new byte[NONCE_BYTES];
        random.nextBytes(headerNonce);
        byte[] headerCiphertext = encrypt(
                ByteBuffer.allocate(Long.BYTES).putLong(expiresAt).array(), headerNonce,
                headerAad(evidenceId, version));
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(HEADER_BYTES + ciphertext.length);
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeInt(MAGIC);
        out.writeByte(version);
        out.write(headerNonce);
        out.write(headerCiphertext);
        out.write(nonce);
        out.write(ciphertext);
        out.flush();
        return bytes.toByteArray();
    }

    private Envelope decode(byte[] encoded, UUID evidenceId) throws IOException {
        if (encoded.length < HEADER_BYTES + TAG_BYTES) throw new IOException("truncated evidence envelope");
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(encoded));
        if (in.readInt() != MAGIC) throw new IOException("invalid evidence envelope");
        int version = in.readUnsignedByte();
        if (version != VERSION_V1 && version != VERSION_V2) throw new IOException("invalid evidence envelope");
        byte[] headerNonce = in.readNBytes(NONCE_BYTES);
        byte[] headerCiphertext = in.readNBytes(HEADER_CIPHERTEXT_BYTES);
        try {
            byte[] expiryBytes = decrypt(headerNonce, headerCiphertext,
                    version == VERSION_V1 ? evidenceId.toString().getBytes(StandardCharsets.US_ASCII) : headerAad(evidenceId, version));
            if (expiryBytes.length != Long.BYTES) throw new IOException("invalid evidence expiration header");
            long expiresAt = ByteBuffer.wrap(expiryBytes).getLong();
            java.util.Arrays.fill(expiryBytes, (byte) 0);
            
            byte[] nonce = in.readNBytes(NONCE_BYTES);
            byte[] ciphertext = in.readNBytes(encoded.length - HEADER_BYTES);
            if (nonce.length != NONCE_BYTES || ciphertext.length < TAG_BYTES) {
                throw new IOException("truncated evidence envelope");
            }
            return new Envelope(nonce, ciphertext, expiresAt, version);
        } catch (IOException exception) {
            throw new IOException("invalid evidence expiration header", exception);
        }
    }

    private long decodeHeader(Path path) throws IOException {
        byte[] header = new byte[HEADER_BYTES];
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            ByteBuffer buffer = ByteBuffer.wrap(header);
            while (buffer.hasRemaining() && channel.read(buffer) > 0) { }
        }
        if (bufferMagic(header) != MAGIC || ((header[4] & 0xff) != VERSION_V1 && (header[4] & 0xff) != VERSION_V2)) throw new IOException("invalid evidence envelope");
        UUID evidenceId;
        try { evidenceId = UUID.fromString(path.getFileName().toString().replaceFirst("\\.mce$", "")); }
        catch (IllegalArgumentException exception) { throw new IOException("invalid evidence filename", exception); }
        byte[] headerNonce = java.util.Arrays.copyOfRange(header, 5, 5 + NONCE_BYTES);
        byte[] headerCiphertext = java.util.Arrays.copyOfRange(header, 5 + NONCE_BYTES, HEADER_BYTES - NONCE_BYTES);
        int version = header[4] & 0xff;
        try {
            byte[] expiry = decrypt(headerNonce, headerCiphertext,
                    version == VERSION_V1 ? evidenceId.toString().getBytes(StandardCharsets.US_ASCII) : headerAad(evidenceId, version));
            try {
                if (expiry.length != Long.BYTES) throw new IOException("invalid evidence expiration header");
                return ByteBuffer.wrap(expiry).getLong();
            } finally {
                java.util.Arrays.fill(expiry, (byte) 0);
            }
        } catch (IOException exception) {
            throw new IOException("invalid evidence expiration header", exception);
        }
    }

    private static int bufferMagic(byte[] header) { return ByteBuffer.wrap(header, 0, 4).getInt(); }
    private ReviewPlain decryptV2(Envelope envelope, UUID evidenceId) throws IOException {
        byte[] plaintext = decrypt(envelope.nonce, envelope.ciphertext, v2Aad(evidenceId, envelope.expiresAtEpochMs));
        try { return deserializeV2(plaintext); }
        finally { java.util.Arrays.fill(plaintext, (byte) 0); }
    }
    private static byte[] headerAad(UUID evidenceId, int version) {
        return ("MCAce evidence header v" + version + "\0" + evidenceId).getBytes(StandardCharsets.US_ASCII);
    }
    private static byte[] v2Aad(UUID evidenceId, long expiresAt) {
        return ("MCAce evidence v2\0" + evidenceId + "\0" + expiresAt).getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] serializeV2(EvidenceStorageMetadata metadata, byte[] content) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(Math.addExact(1024, content.length));
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeUTF("MCAce evidence v2");
            out.writeLong(metadata.evidenceId().getMostSignificantBits()); out.writeLong(metadata.evidenceId().getLeastSignificantBits());
            out.writeLong(metadata.playerId().getMostSignificantBits()); out.writeLong(metadata.playerId().getLeastSignificantBits());
            out.writeUTF(metadata.sessionId()); out.writeUTF(metadata.requestId()); out.writeUTF(metadata.caseId());
            out.writeInt(metadata.type().getNumber()); out.writeInt(metadata.captureScope().getNumber()); out.writeInt(metadata.status().getNumber());
            out.writeLong(metadata.capturedAt().toEpochMilli()); out.writeInt(metadata.widthPixels()); out.writeInt(metadata.heightPixels()); out.writeInt(metadata.totalChunks());
            out.write(metadata.contentSha256()); out.write(metadata.merkleRootSha256()); out.writeLong(metadata.retentionSeconds());
            out.writeUTF(metadata.retentionPolicyId()); out.writeUTF(metadata.retentionPurpose()); out.writeInt(content.length); out.write(content); out.flush();
            return bytes.toByteArray();
        }
    }

    private ReviewPlain deserializeV2(byte[] plaintext) throws IOException {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(plaintext))) {
            if (!"MCAce evidence v2".equals(in.readUTF())) throw new IOException("invalid v2 evidence domain");
            UUID evidenceId = new UUID(in.readLong(), in.readLong()); UUID playerId = new UUID(in.readLong(), in.readLong());
            String session = in.readUTF(), request = in.readUTF(), caseId = in.readUTF();
            com.ellan.mcace.protocol.generated.EvidenceType type = com.ellan.mcace.protocol.generated.EvidenceType.forNumber(in.readInt());
            com.ellan.mcace.protocol.generated.EvidenceCaptureScope scope = com.ellan.mcace.protocol.generated.EvidenceCaptureScope.forNumber(in.readInt());
            com.ellan.mcace.protocol.generated.EvidenceCollectionStatus status = com.ellan.mcace.protocol.generated.EvidenceCollectionStatus.forNumber(in.readInt());
            long capturedAt = in.readLong(); int width = in.readInt(), height = in.readInt(), chunks = in.readInt();
            byte[] contentHash = in.readNBytes(32), merkle = in.readNBytes(32); long retention = in.readLong();
            String policy = in.readUTF(), purpose = in.readUTF(); int length = in.readInt();
            if (type == null || scope == null || status == null || type == com.ellan.mcace.protocol.generated.EvidenceType.UNRECOGNIZED
                    || scope == com.ellan.mcace.protocol.generated.EvidenceCaptureScope.UNRECOGNIZED
                    || status == com.ellan.mcace.protocol.generated.EvidenceCollectionStatus.UNRECOGNIZED
                    || type == com.ellan.mcace.protocol.generated.EvidenceType.EVIDENCE_UNSPECIFIED
                    || scope == com.ellan.mcace.protocol.generated.EvidenceCaptureScope.EVIDENCE_CAPTURE_SCOPE_UNSPECIFIED
                    || status == com.ellan.mcace.protocol.generated.EvidenceCollectionStatus.EVIDENCE_COLLECTION_STATUS_UNSPECIFIED
                    || length <= 0 || length > maxBytes || contentHash.length != 32 || merkle.length != 32) throw new IOException("invalid v2 evidence fields");
            byte[] content = in.readNBytes(length);
            if (content.length != length || in.available() != 0) throw new IOException("truncated or trailing v2 evidence");
            try {
                EvidenceStorageMetadata metadata = new EvidenceStorageMetadata(evidenceId, playerId, session, request, caseId, type, scope, status,
                        java.time.Instant.ofEpochMilli(capturedAt), width, height, chunks, contentHash, merkle, retention, policy, purpose);
                if (retention != disclosure.retentionSeconds() || !policy.equals(disclosure.retentionPolicyId())
                        || !purpose.equals(disclosure.retentionPurpose())) throw new IOException("v2 evidence retention disclosure mismatch");
                return new ReviewPlain(metadata, content);
            } catch (IOException | IllegalArgumentException exception) {
                java.util.Arrays.fill(content, (byte) 0);
                throw exception;
            }
        } catch (IllegalArgumentException exception) { throw new IOException("invalid v2 evidence metadata", exception); }
    }
    private static byte[] sha256(byte[] value) {
        try { return java.security.MessageDigest.getInstance("SHA-256").digest(value); }
        catch (java.security.NoSuchAlgorithmException exception) { throw new AssertionError(exception); }
    }

    private static byte[] readBounded(Path path, int size) throws IOException {
        byte[] bytes = new byte[size];
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                int read = channel.read(buffer);
                if (read < 0) throw new IOException("truncated evidence envelope");
            }
        }
        return bytes;
    }

    private record Inventory(long fileCount, long totalBytes) { }
    private record Envelope(byte[] nonce, byte[] ciphertext, long expiresAtEpochMs, int version) { }
    private record ReviewPlain(EvidenceStorageMetadata metadata, byte[] content) { }
}
