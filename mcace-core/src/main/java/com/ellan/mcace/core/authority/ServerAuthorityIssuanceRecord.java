package com.ellan.mcace.core.authority;

import com.ellan.mcace.protocol.ProtocolConstants;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Content-free durable proof that one exact authority frame was issued by Paper/Folia. */
record ServerAuthorityIssuanceRecord(
        UUID attestationId,
        String backendKeyIdSha256,
        long observationSequence,
        String sessionBindingCommitmentSha256,
        String authorityProfileSha256,
        String providerEvidenceCommitmentSha256,
        Instant observedAt,
        Instant issuedAt,
        Instant expiresAt,
        String signedFrameSha256) {
    ServerAuthorityIssuanceRecord {
        Objects.requireNonNull(attestationId, "attestationId");
        backendKeyIdSha256 = BackendAuthorityPin.sha256(
                backendKeyIdSha256, "backendKeyIdSha256");
        if (observationSequence <= 0) {
            throw new IllegalArgumentException("observationSequence must be positive");
        }
        sessionBindingCommitmentSha256 = BackendAuthorityPin.sha256(
                sessionBindingCommitmentSha256, "sessionBindingCommitmentSha256");
        authorityProfileSha256 = BackendAuthorityPin.sha256(
                authorityProfileSha256, "authorityProfileSha256");
        providerEvidenceCommitmentSha256 = BackendAuthorityPin.sha256(
                providerEvidenceCommitmentSha256, "providerEvidenceCommitmentSha256");
        Objects.requireNonNull(observedAt, "observedAt");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (!millisecondPrecise(observedAt) || !millisecondPrecise(issuedAt)
                || !millisecondPrecise(expiresAt) || observedAt.isAfter(issuedAt)
                || !expiresAt.isAfter(issuedAt)
                || Duration.between(issuedAt, expiresAt)
                .compareTo(ProtocolConstants.MAX_BACKEND_AUTHORITY_TTL) > 0) {
            throw new IllegalArgumentException("invalid issuance time range");
        }
        signedFrameSha256 = BackendAuthorityPin.sha256(
                signedFrameSha256, "signedFrameSha256");
    }

    private static boolean millisecondPrecise(Instant value) {
        return Instant.ofEpochMilli(value.toEpochMilli()).equals(value);
    }
}
