package com.ellan.mcace.core.evidence;

import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import com.ellan.mcace.protocol.generated.EvidenceType;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Content-free metadata authenticated as AES-GCM AAD for one stored transfer. */
public record EvidenceStorageMetadata(
        UUID evidenceId, UUID playerId, String sessionId, String requestId, String caseId,
        EvidenceType type, EvidenceCaptureScope captureScope, EvidenceCollectionStatus status,
        Instant capturedAt, int widthPixels, int heightPixels, int totalChunks,
        byte[] contentSha256, byte[] merkleRootSha256,
        long retentionSeconds, String retentionPolicyId, String retentionPurpose) {
    public EvidenceStorageMetadata(
            UUID evidenceId, UUID playerId, String sessionId, String requestId, String caseId,
            EvidenceType type, EvidenceCaptureScope captureScope, EvidenceCollectionStatus status,
            Instant capturedAt, int widthPixels, int heightPixels, int totalChunks,
            byte[] contentSha256, byte[] merkleRootSha256) {
        this(evidenceId, playerId, sessionId, requestId, caseId, type, captureScope, status, capturedAt,
                widthPixels, heightPixels, totalChunks, contentSha256, merkleRootSha256, 0, "", "");
    }

    public EvidenceStorageMetadata {
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
        Objects.requireNonNull(retentionPolicyId, "retentionPolicyId");
        Objects.requireNonNull(retentionPurpose, "retentionPurpose");
        if (sessionId.isBlank() || requestId.isBlank() || caseId.isBlank()
                || sessionId.length() > 128 || requestId.length() > 128 || caseId.length() > 128
                || containsControl(sessionId) || containsControl(requestId) || containsControl(caseId)
                || widthPixels < 0 || heightPixels < 0 || totalChunks < 0
                || retentionSeconds < 0 || retentionPolicyId.length() > 128 || retentionPurpose.length() > 256
                || containsControl(retentionPolicyId) || containsControl(retentionPurpose)
                || contentSha256.length != 32 || merkleRootSha256.length != 32) {
            throw new IllegalArgumentException("invalid evidence storage metadata");
        }
        contentSha256 = contentSha256.clone();
        merkleRootSha256 = merkleRootSha256.clone();
    }

    @Override public byte[] contentSha256() { return contentSha256.clone(); }
    @Override public byte[] merkleRootSha256() { return merkleRootSha256.clone(); }

    /** Stable, length-delimited bytes; no user-controlled path or raw content is included. */
    public byte[] aad() {
        try {
            java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream(512);
            java.io.DataOutputStream out = new java.io.DataOutputStream(bytes);
            out.writeUTF("MCAce evidence AAD v1");
            out.writeUTF(evidenceId.toString());
            out.writeUTF(playerId.toString());
            out.writeUTF(sessionId);
            out.writeUTF(requestId);
            out.writeUTF(caseId);
            out.writeUTF(type.name());
            out.writeUTF(captureScope.name());
            out.writeUTF(status.name());
            out.writeLong(capturedAt.toEpochMilli());
            out.writeInt(widthPixels);
            out.writeInt(heightPixels);
            out.writeInt(totalChunks);
            out.write(contentSha256);
            out.write(merkleRootSha256);
            out.writeLong(retentionSeconds);
            out.writeUTF(retentionPolicyId);
            out.writeUTF(retentionPurpose);
            out.flush();
            return bytes.toByteArray();
        } catch (java.io.IOException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static boolean containsControl(String value) {
        return value.chars().anyMatch(Character::isISOControl);
    }
}
