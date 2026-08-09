package com.ellan.mcace.core.persistence;

import com.ellan.mcace.protocol.generated.EvidenceType;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record EvidenceMetadataDraft(
        UUID evidenceId,
        UUID playerId,
        String sessionId,
        EvidenceType type,
        ObservationOrigin origin,
        Instant capturedAt,
        long contentSize,
        byte[] contentSha256,
        String storageUri,
        String operatorId) {
    public EvidenceMetadataDraft {
        Objects.requireNonNull(evidenceId, "evidenceId");
        Objects.requireNonNull(playerId, "playerId");
        sessionId = Objects.requireNonNull(sessionId, "sessionId");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(origin, "origin");
        Objects.requireNonNull(capturedAt, "capturedAt");
        Objects.requireNonNull(contentSha256, "contentSha256");
        storageUri = Objects.requireNonNull(storageUri, "storageUri");
        operatorId = Objects.requireNonNull(operatorId, "operatorId");
        if (type == EvidenceType.EVIDENCE_UNSPECIFIED || type == EvidenceType.UNRECOGNIZED
                || contentSize < 0 || contentSha256.length != 32 || storageUri.isBlank()) {
            throw new IllegalArgumentException("invalid evidence metadata draft");
        }
        contentSha256 = contentSha256.clone();
    }

    @Override public byte[] contentSha256() { return contentSha256.clone(); }
}
