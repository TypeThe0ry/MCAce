package com.ellan.mcace.protocol.evidence;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.EvidenceBegin;
import com.ellan.mcace.protocol.generated.EvidenceChunk;
import com.ellan.mcace.protocol.generated.EvidenceCommit;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceRequest;
import com.ellan.mcace.protocol.generated.EvidenceResponse;
import com.ellan.mcace.protocol.generated.EvidenceType;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.Objects;
import java.util.UUID;

/** Validates advertised evidence dimensions before allocating or accepting upload data. */
public final class EvidenceTransferLimits {
    private EvidenceTransferLimits() {
    }

    /**
     * Creates the isolated replay budget required by one accepted evidence request. The caller
     * must create this only after a signed, unexpired, single-use request has been accepted; it
     * must not replace the shared handshake replay guard.
     */
    public static NonceReplayGuard newRequestReplayGuard(Clock clock, EvidenceRequest request) {
        Objects.requireNonNull(request, "request");
        return new NonceReplayGuard(
                Objects.requireNonNull(clock, "clock"),
                ProtocolConstants.MAX_EVIDENCE_REQUEST_TTL,
                ProtocolConstants.MAX_EVIDENCE_REPLAY_ENTRIES_PER_REQUEST,
                ProtocolConstants.MAX_EVIDENCE_REPLAY_ENTRIES_PER_REQUEST);
    }

    public static NonceReplayGuard newRequestReplayGuard(
            Clock clock, EvidenceRequestVerifier.VerifiedRequest verifiedRequest) {
        Objects.requireNonNull(verifiedRequest, "verifiedRequest");
        return newRequestReplayGuard(clock, verifiedRequest.request());
    }

    public static void validateRequest(EvidenceRequest request, long nowEpochMs) {
        Objects.requireNonNull(request, "request");
        requireIdentifier(request.getEvidenceId());
        requireIdentifier(request.getRequestId());
        requireCanonicalPlayerId(request.getPlayerId());
        requireTypeAndScope(request.getType(), request.getCaptureScope());
        validateRetentionDisclosure(request);
        if (request.getType() == EvidenceType.SCREENSHOT && !request.getAllowedRelativePathsList().isEmpty()) {
            throw new IllegalArgumentException("screenshot requests must not carry filesystem paths");
        }
        requireOptionalIdentifier(request.getCaseId(), "case id");
        long expiry = request.getExpiresAtEpochMs();
        if (expiry <= nowEpochMs || expiry - nowEpochMs < 0L
                || expiry > saturatingAdd(nowEpochMs, ProtocolConstants.MAX_EVIDENCE_REQUEST_TTL.toMillis())) {
            throw new IllegalArgumentException("evidence request is expired or exceeds its short TTL");
        }
    }

    /** Validates the signed, user-visible raw-content retention disclosure. */
    public static void validateRetentionDisclosure(EvidenceRequest request) {
        Objects.requireNonNull(request, "request");
        boolean retained = request.getRawContentRetained();
        boolean hasPolicy = !request.getRetentionPolicyId().isEmpty();
        boolean hasPurpose = !request.getRetentionPurpose().isEmpty();
        if (!retained) {
            if (request.getRetentionSeconds() != 0L || hasPolicy || hasPurpose) {
                throw new IllegalArgumentException("non-retained evidence must have zero retention disclosure");
            }
            return;
        }
        if (request.getCaptureScope() == EvidenceCaptureScope.GAME_WINDOW
                || request.getCaptureScope() == EvidenceCaptureScope.DESKTOP) {
            throw new IllegalArgumentException("unsupported capture scopes cannot retain raw content");
        }
        if (request.getRetentionSeconds() == 0L
                || request.getRetentionSeconds() > ProtocolConstants.MAX_EVIDENCE_RETENTION_SECONDS) {
            throw new IllegalArgumentException("evidence retention exceeds configured bound");
        }
        requireRetentionText(request.getRetentionPolicyId(),
                ProtocolConstants.MAX_EVIDENCE_RETENTION_POLICY_ID_CHARS, "retention policy id");
        requireRetentionText(request.getRetentionPurpose(),
                ProtocolConstants.MAX_EVIDENCE_RETENTION_PURPOSE_CHARS, "retention purpose");
    }

    public static void validateResponse(EvidenceResponse response, EvidenceRequest request, long nowEpochMs) {
        Objects.requireNonNull(response, "response");
        Objects.requireNonNull(request, "request");
        requireIdentifier(response.getEvidenceId());
        requireIdentifier(response.getRequestId());
        requireIdentifier(response.getPlayerId());
        if (!response.getEvidenceId().equals(request.getEvidenceId())
                || !response.getRequestId().equals(request.getRequestId())
                || !response.getPlayerId().equals(request.getPlayerId())
                || response.getType() != request.getType()
                || response.getCaptureScope() != request.getCaptureScope()) {
            throw new IllegalArgumentException("evidence response is not bound to its request");
        }
        requireStatus(response.getCollectionStatusCode());
        if (response.getCollectionStatusCode() == EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED) {
            if (request.getCaptureScope() != EvidenceCaptureScope.GAME_RENDER_FRAME
                    || response.getContent().isEmpty()
                    || response.getContent().size() > ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES
                    || response.getCapturedAtEpochMs() <= 0L
                    || response.getCapturedAtEpochMs() > nowEpochMs
                    || response.getContentSha256().size() != 32
                    || !MessageDigest.isEqual(
                            sha256(response.getContent().toByteArray()), response.getContentSha256().toByteArray())) {
                throw new IllegalArgumentException("collected game-frame evidence response is invalid");
            }
            return;
        }
        if (request.getCaptureScope() != EvidenceCaptureScope.GAME_RENDER_FRAME
                && response.getCollectionStatusCode() != EvidenceCollectionStatus.EVIDENCE_COLLECTION_DECLINED
                && response.getCollectionStatusCode() != EvidenceCollectionStatus.EVIDENCE_COLLECTION_UNAVAILABLE
                && response.getCollectionStatusCode() != EvidenceCollectionStatus.EVIDENCE_COLLECTION_UNSUPPORTED) {
            throw new IllegalArgumentException("window or desktop evidence must be declined or unavailable");
        }
        if (!response.getContent().isEmpty() || !response.getContentSha256().isEmpty()) {
            throw new IllegalArgumentException("rejected evidence response must not contain content");
        }
    }

    public static void validateBegin(EvidenceBegin begin) {
        validateBegin(begin, Long.MAX_VALUE);
    }

    public static void validateBegin(EvidenceBegin begin, long nowEpochMs) {
        Objects.requireNonNull(begin, "begin");
        requireIdentifier(begin.getEvidenceId());
        requireIdentifier(begin.getRequestId());
        requireIdentifier(begin.getPlayerId());
        requirePositiveSequence(begin.getTransportSequence());
        requireTypeAndScope(begin.getType(), begin.getCaptureScope());
        requireStatus(begin.getCollectionStatus());
        if (begin.getCollectionStatus() != EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED) {
            if (begin.getTotalBytes() != 0 || begin.getTotalChunks() != 0
                    || begin.getWidthPixels() != 0 || begin.getHeightPixels() != 0
                    || !begin.getContentSha256().isEmpty() || !begin.getMerkleRootSha256().isEmpty()) {
                throw new IllegalArgumentException("non-collected evidence must not advertise content");
            }
            return;
        }
        if (begin.getType() == EvidenceType.SCREENSHOT
                && begin.getCaptureScope() != EvidenceCaptureScope.GAME_RENDER_FRAME) {
            throw new IllegalArgumentException("only game-render-frame screenshots are supported");
        }
        if (begin.getCapturedAtEpochMs() <= 0L || begin.getCapturedAtEpochMs() > nowEpochMs) {
            throw new IllegalArgumentException("collected evidence timestamp is invalid");
        }
        validateTransferShape(begin.getTotalBytes(), begin.getTotalChunks());
        validatePixels(begin.getWidthPixels(), begin.getHeightPixels());
        requireSha256(begin.getContentSha256().size(), "content hash");
        requireSha256(begin.getMerkleRootSha256().size(), "Merkle root");
    }

    public static void validateChunk(EvidenceChunk chunk, EvidenceBegin begin) {
        Objects.requireNonNull(chunk, "chunk");
        Objects.requireNonNull(begin, "begin");
        requireIdentifier(chunk.getEvidenceId());
        if (!chunk.getEvidenceId().equals(begin.getEvidenceId())) {
            throw new IllegalArgumentException("chunk evidence id does not match begin");
        }
        if (!chunk.getRequestId().equals(begin.getRequestId()) || !chunk.getPlayerId().equals(begin.getPlayerId())
                || chunk.getTransportSequence() == 0L) {
            throw new IllegalArgumentException("chunk is not bound to begin");
        }
        if (begin.getCollectionStatus() != EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED
                || chunk.getChunkIndex() >= begin.getTotalChunks()) {
            throw new IllegalArgumentException("chunk is not permitted by evidence begin");
        }
        if (chunk.getContent().size() == 0 || chunk.getContent().size() > ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES) {
            throw new IllegalArgumentException("evidence chunk exceeds bounded size");
        }
        requireSha256(chunk.getChunkSha256().size(), "chunk hash");
        byte[] calculated = sha256(chunk.getContent().toByteArray());
        if (!MessageDigest.isEqual(calculated, chunk.getChunkSha256().toByteArray())) {
            throw new IllegalArgumentException("evidence chunk hash does not match content");
        }
    }

    public static void validateCommit(EvidenceCommit commit, EvidenceBegin begin) {
        Objects.requireNonNull(commit, "commit");
        Objects.requireNonNull(begin, "begin");
        requireIdentifier(commit.getEvidenceId());
        if (!commit.getEvidenceId().equals(begin.getEvidenceId())
                || !commit.getRequestId().equals(begin.getRequestId())
                || !commit.getPlayerId().equals(begin.getPlayerId())
                || commit.getTransportSequence() == 0L
                || commit.getTotalBytes() != begin.getTotalBytes()
                || commit.getTotalChunks() != begin.getTotalChunks()
                || commit.getCollectionStatus() != begin.getCollectionStatus()
                || !MessageDigest.isEqual(
                        commit.getContentSha256().toByteArray(), begin.getContentSha256().toByteArray())
                || !MessageDigest.isEqual(
                        commit.getMerkleRootSha256().toByteArray(), begin.getMerkleRootSha256().toByteArray())) {
            throw new IllegalArgumentException("evidence commit does not match begin");
        }
        if (begin.getCollectionStatus() != EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED) {
            if (commit.getTotalBytes() != 0L || commit.getTotalChunks() != 0
                    || !commit.getContentSha256().isEmpty() || !commit.getMerkleRootSha256().isEmpty()) {
                throw new IllegalArgumentException("non-collected evidence commit must not advertise content");
            }
            return;
        }
        requireSha256(commit.getContentSha256().size(), "content hash");
        requireSha256(commit.getMerkleRootSha256().size(), "Merkle root");
        validateTransferShape(commit.getTotalBytes(), commit.getTotalChunks());
    }

    private static void validateTransferShape(long totalBytes, int totalChunks) {
        if (totalBytes <= 0 || totalBytes > ProtocolConstants.MAX_EVIDENCE_TOTAL_BYTES
                || totalChunks <= 0 || totalChunks > ProtocolConstants.MAX_EVIDENCE_CHUNKS) {
            throw new IllegalArgumentException("evidence transfer exceeds configured bounds");
        }
        long minimumChunks = (totalBytes + ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES - 1)
                / ProtocolConstants.MAX_EVIDENCE_CHUNK_BYTES;
        if (totalChunks < minimumChunks) {
            throw new IllegalArgumentException("evidence transfer has too few chunks for its declared size");
        }
    }

    private static void validatePixels(int width, int height) {
        if (width <= 0 || height <= 0 || (long) width * height > ProtocolConstants.MAX_EVIDENCE_PIXELS) {
            throw new IllegalArgumentException("evidence image exceeds pixel bounds");
        }
    }

    private static void requireIdentifier(String evidenceId) {
        if (evidenceId == null || evidenceId.isBlank() || evidenceId.length() > 128
                || containsIsoControl(evidenceId)) {
            throw new IllegalArgumentException("evidence id is required");
        }
    }

    private static void requireOptionalIdentifier(String value, String name) {
        if (value != null && !value.isEmpty()) {
            if (value.length() > 128 || containsIsoControl(value)) {
                throw new IllegalArgumentException(name + " is invalid");
            }
        }
    }

    private static void requireCanonicalPlayerId(String playerId) {
        requireIdentifier(playerId);
        try {
            if (!UUID.fromString(playerId).toString().equals(playerId)) {
                throw new IllegalArgumentException("player id must be canonical UUID");
            }
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("player id must be canonical UUID", exception);
        }
    }

    private static boolean containsIsoControl(String value) {
        return value.chars().anyMatch(Character::isISOControl);
    }

    private static void requireRetentionText(String value, int maxChars, String name) {
        if (value == null || value.isBlank() || value.length() > maxChars || containsIsoControl(value)) {
            throw new IllegalArgumentException(name + " is required and bounded");
        }
    }

    private static void requireTypeAndScope(EvidenceType type, EvidenceCaptureScope scope) {
        if (type == EvidenceType.EVIDENCE_UNSPECIFIED || type == EvidenceType.UNRECOGNIZED) {
            throw new IllegalArgumentException("evidence type is required");
        }
        boolean screenshot = type == EvidenceType.SCREENSHOT;
        boolean captureScope = scope != EvidenceCaptureScope.EVIDENCE_CAPTURE_SCOPE_UNSPECIFIED
                && scope != EvidenceCaptureScope.UNRECOGNIZED;
        if (screenshot != captureScope) {
            throw new IllegalArgumentException("screenshot evidence requires exactly one explicit capture scope");
        }
    }

    private static void requireStatus(EvidenceCollectionStatus status) {
        if (status == EvidenceCollectionStatus.EVIDENCE_COLLECTION_STATUS_UNSPECIFIED
                || status == EvidenceCollectionStatus.UNRECOGNIZED) {
            throw new IllegalArgumentException("evidence collection status is required");
        }
    }

    private static void requireSha256(int size, String name) {
        if (size != 32) {
            throw new IllegalArgumentException(name + " must contain 32 bytes");
        }
    }

    private static byte[] sha256(byte[] content) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(content);
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static void requirePositiveSequence(long sequence) {
        if (sequence == 0L) {
            throw new IllegalArgumentException("evidence transport sequence must be positive");
        }
    }

    public static boolean isStrictlyIncreasingUnsigned(long previous, long candidate) {
        return candidate != 0L && Long.compareUnsigned(candidate, previous) > 0;
    }

    public static long nextUnsignedSequence(long current) {
        if (current == -1L) {
            throw new IllegalArgumentException("evidence transport sequence exhausted");
        }
        long next = current + 1L;
        if (next == 0L) {
            throw new IllegalArgumentException("evidence transport sequence wrapped to zero");
        }
        return next;
    }

    private static long saturatingAdd(long left, long right) {
        if (right > 0L && left > Long.MAX_VALUE - right) {
            return Long.MAX_VALUE;
        }
        return left + right;
    }
}
