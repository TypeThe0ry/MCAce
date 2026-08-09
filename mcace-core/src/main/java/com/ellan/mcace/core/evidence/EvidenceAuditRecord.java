package com.ellan.mcace.core.evidence;

import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import com.ellan.mcace.protocol.generated.EvidenceType;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/** Content-free audit summary retaining request, scope, outcome, and transfer dimensions. */
public record EvidenceAuditRecord(
        UUID evidenceId, UUID playerId, String sessionId, String requestId, String caseId,
        EvidenceType type, EvidenceCaptureScope captureScope, EvidenceCollectionStatus status,
        Instant capturedAt, long contentSize, int totalChunks, int widthPixels, int heightPixels,
        byte[] contentSha256, byte[] merkleRootSha256, String storageUri, String operatorId) {
    public EvidenceAuditRecord {
        Objects.requireNonNull(evidenceId, "evidenceId");
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(requestId, "requestId");
        Objects.requireNonNull(caseId, "caseId");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(captureScope, "captureScope");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(capturedAt, "capturedAt");
        Objects.requireNonNull(contentSha256, "contentSha256");
        Objects.requireNonNull(merkleRootSha256, "merkleRootSha256");
        Objects.requireNonNull(storageUri, "storageUri");
        Objects.requireNonNull(operatorId, "operatorId");
        if (sessionId.isBlank() || requestId.isBlank() || caseId.isBlank() || operatorId.isBlank()
                || contentSize < 0 || totalChunks < 0 || widthPixels < 0 || heightPixels < 0
                || (contentSha256.length != 0 && contentSha256.length != 32)
                || (merkleRootSha256.length != 0 && merkleRootSha256.length != 32)
                || storageUri.isBlank()) {
            throw new IllegalArgumentException("invalid evidence audit record");
        }
        contentSha256 = contentSha256.clone();
        merkleRootSha256 = merkleRootSha256.clone();
    }
    @Override public byte[] contentSha256() { return contentSha256.clone(); }
    @Override public byte[] merkleRootSha256() { return merkleRootSha256.clone(); }
    @Override public boolean equals(Object other) {
        return other instanceof EvidenceAuditRecord that
                && Objects.equals(evidenceId, that.evidenceId) && Objects.equals(playerId, that.playerId)
                && Objects.equals(sessionId, that.sessionId) && Objects.equals(requestId, that.requestId)
                && Objects.equals(caseId, that.caseId) && type == that.type && captureScope == that.captureScope
                && status == that.status && Objects.equals(capturedAt, that.capturedAt)
                && contentSize == that.contentSize && totalChunks == that.totalChunks
                && widthPixels == that.widthPixels && heightPixels == that.heightPixels
                && Arrays.equals(contentSha256, that.contentSha256)
                && Arrays.equals(merkleRootSha256, that.merkleRootSha256)
                && Objects.equals(storageUri, that.storageUri) && Objects.equals(operatorId, that.operatorId);
    }
    @Override public int hashCode() {
        int result = Objects.hash(evidenceId, playerId, sessionId, requestId, caseId, type, captureScope,
                status, capturedAt, contentSize, totalChunks, widthPixels, heightPixels, storageUri, operatorId);
        return 31 * (31 * result + Arrays.hashCode(contentSha256)) + Arrays.hashCode(merkleRootSha256);
    }
}
