package com.ellan.mcace.core.evidence;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import com.ellan.mcace.protocol.generated.EvidenceType;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.CRC32;

/**
 * Explicitly opt-in, loopback-only viewer for one collected game render frame at a time.
 *
 * <p>The service deliberately owns neither encrypted storage nor proxy transport. A review link
 * is an unguessable, single-use capability and is consumed before the reader is called.</p>
 */
public final class LoopbackEvidenceReviewService implements AutoCloseable {
    private static final String PATH_PREFIX = "/mcace/evidence/";
    private static final int TOKEN_BYTES = 32;
    private static final int TOKEN_LENGTH = 43;
    private static final int MAX_REQUEST_HEADER_BYTES = 8 * 1024;
    private static final int WORKER_QUEUE_CAPACITY = 16;
    private static final byte[] PNG_SIGNATURE = new byte[] {
            (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
    };

    private final EvidenceReviewReader reader;
    private final EvidenceAuditSink auditSink;
    private final Clock clock;
    private final SecureRandom random;
    private final ServerSocket server;
    private final InetSocketAddress localBind;
    private final Duration tokenTtl;
    private final int maxTokens;
    private final ThreadPoolExecutor workers;
    private final Map<String, Grant> grants = new HashMap<>();
    private final java.util.Set<Socket> activeSockets = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final Thread acceptThread;

    private LoopbackEvidenceReviewService(
            EvidenceReviewReader reader, EvidenceAuditSink auditSink, Clock clock, SecureRandom random,
            InetAddress bind, int port, Duration tokenTtl, int maxTokens) throws IOException {
        this.reader = Objects.requireNonNull(reader, "reader");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.random = Objects.requireNonNull(random, "random");
        this.tokenTtl = validateTtl(tokenTtl);
        this.maxTokens = validateMaxTokens(maxTokens);
        validateBind(bind, port);
        this.server = new ServerSocket();
        this.server.bind(new InetSocketAddress(bind, port), 16);
        this.localBind = (InetSocketAddress) this.server.getLocalSocketAddress();
        ThreadFactory factory = runnable -> {
            Thread thread = new Thread(runnable, "mcace-evidence-review-worker");
            thread.setDaemon(true);
            return thread;
        };
        this.workers = new ThreadPoolExecutor(1, 2, 30L, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(WORKER_QUEUE_CAPACITY), factory, new ThreadPoolExecutor.AbortPolicy());
        this.acceptThread = new Thread(this::acceptLoop, "mcace-evidence-review-accept");
        this.acceptThread.setDaemon(true);
        this.acceptThread.start();
    }

    public static LoopbackEvidenceReviewService start(
            EvidenceReviewReader reader, EvidenceAuditSink auditSink, Clock clock, SecureRandom random,
            InetAddress bind, int port, Duration tokenTtl, int maxTokens) throws IOException {
        return new LoopbackEvidenceReviewService(reader, auditSink, clock, random, bind, port, tokenTtl, maxTokens);
    }

    public synchronized ReviewLink issue(UUID evidenceId, String operatorId, String reason) {
        ensureOpen();
        Objects.requireNonNull(evidenceId, "evidenceId");
        operatorId = bounded(operatorId, "operatorId", 128);
        reason = bounded(reason, "reason", 256);
        EvidenceReviewArtifact artifact;
        try {
            artifact = reader.readForReview(evidenceId).orElse(null);
        } catch (Exception exception) {
            audit(evidenceId, operatorId, reason, EvidenceReviewAuditRecord.Outcome.UNAVAILABLE);
            throw new IllegalStateException("evidence review is unavailable", exception);
        }
        if (!isReviewable(evidenceId, artifact)) {
            audit(evidenceId, operatorId, reason, EvidenceReviewAuditRecord.Outcome.INVALID_ARTIFACT);
            throw new IllegalArgumentException("evidence is not eligible for local review");
        }
        removeExpired();
        if (grants.size() >= maxTokens) {
            throw new IllegalStateException("evidence review token limit reached");
        }
        String token = null;
        for (int attempt = 0; attempt < 16; attempt++) {
            byte[] bytes = new byte[TOKEN_BYTES];
            random.nextBytes(bytes);
            token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
            if (!grants.containsKey(token)) break;
            token = null;
        }
        if (token == null) {
            throw new IllegalStateException("unable to allocate evidence review capability");
        }
        Instant expiresAt = clock.instant().plus(tokenTtl);
        grants.put(token, new Grant(evidenceId, operatorId, reason, expiresAt));
        audit(evidenceId, operatorId, reason, EvidenceReviewAuditRecord.Outcome.ISSUED);
        return new ReviewLink(reviewUri(token), expiresAt);
    }

    public synchronized Status status() {
        removeExpired();
        return new Status(!closed.get(), localBind, grants.size(), maxTokens);
    }

    @Override public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        synchronized (this) {
            grants.clear();
        }
        try {
            server.close();
        } catch (IOException ignored) {
            // Closing is best effort; no external state depends on this listener.
        }
        for (Socket socket : activeSockets) {
            closeQuietly(socket);
        }
        workers.shutdownNow();
        try {
            acceptThread.join(1_000L);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

    private void acceptLoop() {
        while (!closed.get()) {
            Socket socket = null;
            try {
                socket = server.accept();
                if (!socket.getInetAddress().isLoopbackAddress()) {
                    closeQuietly(socket);
                    continue;
                }
                socket.setSoTimeout(5_000);
                activeSockets.add(socket);
                Socket accepted = socket;
                workers.execute(() -> handle(accepted));
            } catch (java.util.concurrent.RejectedExecutionException exception) {
                activeSockets.remove(socket);
                closeQuietly(socket);
            } catch (IOException exception) {
                if (socket != null) {
                    closeQuietly(socket);
                }
                if (!closed.get()) {
                    // The listener remains fail-closed; a transient accept error cannot create a review grant.
                    Thread.yield();
                }
            }
        }
    }

    private void handle(Socket socket) {
        try (socket) {
            Request request = readRequest(socket);
            if (request == null || !"GET".equals(request.method()) || !validTokenPath(request.path())) {
                writeGeneric(socket, 404);
                return;
            }
            Grant grant = consume(request.path().substring(PATH_PREFIX.length()));
            if (grant == null) {
                writeGeneric(socket, 404);
                return;
            }
            if (!clock.instant().isBefore(grant.expiresAt())) {
                audit(grant, EvidenceReviewAuditRecord.Outcome.EXPIRED);
                writeGeneric(socket, 410);
                return;
            }
            EvidenceReviewArtifact artifact;
            try {
                artifact = reader.readForReview(grant.evidenceId()).orElse(null);
            } catch (Exception exception) {
                audit(grant, EvidenceReviewAuditRecord.Outcome.UNAVAILABLE);
                writeGeneric(socket, 503);
                return;
            }
            if (!isReviewable(grant.evidenceId(), artifact)) {
                audit(grant, EvidenceReviewAuditRecord.Outcome.INVALID_ARTIFACT);
                writeGeneric(socket, 503);
                return;
            }
            byte[] content = artifact.content();
            try {
                writePng(socket, content);
                audit(grant, EvidenceReviewAuditRecord.Outcome.SERVED);
            } finally {
                java.util.Arrays.fill(content, (byte) 0);
            }
        } catch (IOException ignored) {
            // Connection failures do not reveal grant validity and cannot restore a consumed grant.
        } finally {
            activeSockets.remove(socket);
        }
    }

    private synchronized Grant consume(String token) {
        return grants.remove(token);
    }

    private synchronized void removeExpired() {
        Instant now = clock.instant();
        grants.entrySet().removeIf(entry -> !now.isBefore(entry.getValue().expiresAt()));
    }

    private boolean isReviewable(UUID evidenceId, EvidenceReviewArtifact artifact) {
        if (artifact == null || !clock.instant().isBefore(artifact.expiresAt())) {
            return false;
        }
        EvidenceStorageMetadata metadata = artifact.metadata();
        byte[] content = artifact.content();
        try {
            return metadata.evidenceId().equals(evidenceId)
                    && artifact.storageFormatVersion() == 2
                    && metadata.type() == EvidenceType.SCREENSHOT
                    && metadata.captureScope() == EvidenceCaptureScope.GAME_RENDER_FRAME
                    && metadata.status() == EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED
                    && content.length > 0 && content.length <= ProtocolConstants.MAX_EVIDENCE_TOTAL_BYTES
                    && MessageDigest.isEqual(sha256(content), metadata.contentSha256())
                    && validPng(content, metadata.widthPixels(), metadata.heightPixels());
        } finally {
            java.util.Arrays.fill(content, (byte) 0);
        }
    }

    private static boolean validPng(byte[] content, int expectedWidth, int expectedHeight) {
        if (content.length < PNG_SIGNATURE.length + 25 || expectedWidth <= 0 || expectedHeight <= 0
                || (long) expectedWidth * expectedHeight > ProtocolConstants.MAX_EVIDENCE_PIXELS) {
            return false;
        }
        for (int index = 0; index < PNG_SIGNATURE.length; index++) {
            if (content[index] != PNG_SIGNATURE[index]) return false;
        }
        int offset = PNG_SIGNATURE.length;
        boolean first = true;
        boolean ended = false;
        boolean hasImageData = false;
        while (offset < content.length) {
            if (content.length - offset < 12) return false;
            long length = unsignedInt(content, offset);
            if (length > Integer.MAX_VALUE || length > content.length - offset - 12L) return false;
            int chunkLength = (int) length;
            int typeOffset = offset + 4;
            int dataOffset = offset + 8;
            int crcOffset = dataOffset + chunkLength;
            CRC32 crc = new CRC32();
            crc.update(content, typeOffset, 4 + chunkLength);
            if (unsignedInt(content, crcOffset) != crc.getValue()) return false;
            boolean ihdr = content[typeOffset] == 'I' && content[typeOffset + 1] == 'H'
                    && content[typeOffset + 2] == 'D' && content[typeOffset + 3] == 'R';
            boolean iend = content[typeOffset] == 'I' && content[typeOffset + 1] == 'E'
                    && content[typeOffset + 2] == 'N' && content[typeOffset + 3] == 'D';
            boolean idat = content[typeOffset] == 'I' && content[typeOffset + 1] == 'D'
                    && content[typeOffset + 2] == 'A' && content[typeOffset + 3] == 'T';
            if (first) {
                if (!ihdr || chunkLength != 13 || unsignedInt(content, dataOffset) != expectedWidth
                        || unsignedInt(content, dataOffset + 4) != expectedHeight) return false;
                first = false;
            }
            if (idat && chunkLength > 0) hasImageData = true;
            if (iend) {
                if (chunkLength != 0 || crcOffset + 4 != content.length) return false;
                ended = true;
                break;
            }
            offset = crcOffset + 4;
        }
        return !first && hasImageData && ended;
    }

    private static long unsignedInt(byte[] bytes, int offset) {
        return ((long) (bytes[offset] & 0xFF) << 24)
                | ((long) (bytes[offset + 1] & 0xFF) << 16)
                | ((long) (bytes[offset + 2] & 0xFF) << 8)
                | (bytes[offset + 3] & 0xFFL);
    }

    private static byte[] sha256(byte[] content) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(content);
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private Request readRequest(Socket socket) throws IOException {
        BufferedInputStream input = new BufferedInputStream(socket.getInputStream());
        byte[] header = new byte[MAX_REQUEST_HEADER_BYTES];
        int length = 0;
        int matched = 0;
        while (length < header.length) {
            int value = input.read();
            if (value < 0) return null;
            header[length++] = (byte) value;
            matched = switch (matched) {
                case 0 -> value == '\r' ? 1 : 0;
                case 1 -> value == '\n' ? 2 : value == '\r' ? 1 : 0;
                case 2 -> value == '\r' ? 3 : 0;
                case 3 -> value == '\n' ? 4 : value == '\r' ? 1 : 0;
                default -> 0;
            };
            if (matched == 4) break;
        }
        if (matched != 4) return null;
        String text = new String(header, 0, length, StandardCharsets.US_ASCII);
        int lineEnd = text.indexOf("\r\n");
        if (lineEnd < 0 || !text.contains("\r\n\r\n")) return null;
        String[] parts = text.substring(0, lineEnd).split(" ", -1);
        if (parts.length != 3 || !"HTTP/1.1".equals(parts[2])) return null;
        return new Request(parts[0], parts[1]);
    }

    private void writePng(Socket socket, byte[] content) throws IOException {
        OutputStream output = socket.getOutputStream();
        writeHeaders(output, 200, "OK", "image/png", content.length);
        output.write(content);
        output.flush();
    }

    private void writeGeneric(Socket socket, int status) throws IOException {
        String reason = switch (status) {
            case 410 -> "Gone";
            case 503 -> "Service Unavailable";
            default -> "Not Found";
        };
        OutputStream output = socket.getOutputStream();
        writeHeaders(output, status, reason, "text/plain; charset=utf-8", 0);
        output.flush();
    }

    private static void writeHeaders(OutputStream output, int status, String reason, String contentType, int length)
            throws IOException {
        String headers = "HTTP/1.1 " + status + " " + reason + "\r\n"
                + "Content-Type: " + contentType + "\r\n"
                + "Content-Length: " + length + "\r\n"
                + "Cache-Control: no-store, max-age=0\r\n"
                + "Pragma: no-cache\r\n"
                + "X-Content-Type-Options: nosniff\r\n"
                + "Content-Security-Policy: sandbox; default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n"
                + "Referrer-Policy: no-referrer\r\n"
                + "Cross-Origin-Opener-Policy: same-origin\r\n"
                + "Connection: close\r\n\r\n";
        output.write(headers.getBytes(StandardCharsets.US_ASCII));
    }

    private URI reviewUri(String token) {
        try {
            return new URI("http", null, localBind.getAddress().getHostAddress(), localBind.getPort(),
                    PATH_PREFIX + token, null, null);
        } catch (java.net.URISyntaxException impossible) {
            throw new IllegalStateException("unable to create loopback evidence URL", impossible);
        }
    }

    private static boolean validTokenPath(String path) {
        if (path == null || !path.startsWith(PATH_PREFIX) || path.length() != PATH_PREFIX.length() + TOKEN_LENGTH) {
            return false;
        }
        for (int index = PATH_PREFIX.length(); index < path.length(); index++) {
            char value = path.charAt(index);
            if (!(value >= 'A' && value <= 'Z') && !(value >= 'a' && value <= 'z')
                    && !(value >= '0' && value <= '9') && value != '-' && value != '_') return false;
        }
        return true;
    }

    private static void validateBind(InetAddress bind, int port) {
        if (bind == null || !bind.isLoopbackAddress() || port < 0 || port > 65_535) {
            throw new IllegalArgumentException("evidence review service requires a loopback bind and valid port");
        }
    }

    private static Duration validateTtl(Duration ttl) {
        ttl = Objects.requireNonNull(ttl, "tokenTtl");
        if (ttl.compareTo(Duration.ofSeconds(10)) < 0 || ttl.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("evidence review token TTL must be 10 seconds through 5 minutes");
        }
        return ttl;
    }

    private static int validateMaxTokens(int maxTokens) {
        if (maxTokens < 1 || maxTokens > 128) {
            throw new IllegalArgumentException("evidence review maximum tokens must be 1 through 128");
        }
        return maxTokens;
    }

    private static String bounded(String value, String name, int maximum) {
        value = Objects.requireNonNull(value, name).strip();
        if (value.isEmpty() || value.length() > maximum || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("invalid " + name);
        }
        return value;
    }

    private void ensureOpen() {
        if (closed.get()) throw new IllegalStateException("evidence review service is closed");
    }

    private void audit(Grant grant, EvidenceReviewAuditRecord.Outcome outcome) {
        audit(grant.evidenceId(), grant.operatorId(), grant.reason(), outcome);
    }

    private void audit(UUID evidenceId, String operatorId, String reason, EvidenceReviewAuditRecord.Outcome outcome) {
        try {
            auditSink.appendReview(new EvidenceReviewAuditRecord(evidenceId, clock.instant(), operatorId, reason, outcome));
        } catch (RuntimeException ignored) {
            // Audit output cannot turn a local review into admission or enforcement authority.
        }
    }

    private static void closeQuietly(Socket socket) {
        if (socket == null) return;
        try {
            socket.close();
        } catch (IOException ignored) {
            // No-op.
        }
    }

    public record ReviewLink(URI url, Instant expiresAt) {
        public ReviewLink {
            Objects.requireNonNull(url, "url");
            Objects.requireNonNull(expiresAt, "expiresAt");
        }
    }

    public record Status(boolean running, InetSocketAddress bind, int activeTokens, int maxTokens) {
        public Status {
            Objects.requireNonNull(bind, "bind");
            if (activeTokens < 0 || maxTokens < 1 || activeTokens > maxTokens) {
                throw new IllegalArgumentException("invalid review service status");
            }
        }
    }

    private record Grant(UUID evidenceId, String operatorId, String reason, Instant expiresAt) { }
    private record Request(String method, String path) { }
}
