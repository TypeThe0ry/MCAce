package com.ellan.mcace.core.authority;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A durable issuance capability created only after its matching record was forced to disk.
 *
 * <p>The constructor and undurable codec result are package-private so an adapter cannot
 * manufacture a pre-commit capability. The public transport accessor exists only on this durable
 * token. It contains no disposition action and is not accepted by any proxy executor.</p>
 */
public final class DurablyIssuedServerAuthorityObservation {
    private final byte[] frame;
    private final UUID attestationId;
    private final long observationSequence;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private final String signedFrameSha256;
    private final UUID grantId;
    private final String grantCommitmentSha256;
    private final String lifecycleCommitmentSha256;
    private final String backendKeyIdSha256;
    private final String authorityProfileSha256;
    private final String providerEvidenceCommitmentSha256;

    DurablyIssuedServerAuthorityObservation(
            byte[] frame,
            UUID attestationId,
            long observationSequence,
            Instant issuedAt,
            Instant expiresAt,
            String signedFrameSha256,
            UUID grantId,
            String grantCommitmentSha256,
            String lifecycleCommitmentSha256,
            String backendKeyIdSha256,
            String authorityProfileSha256,
            String providerEvidenceCommitmentSha256) {
        this.frame = Objects.requireNonNull(frame, "frame").clone();
        this.attestationId = Objects.requireNonNull(attestationId, "attestationId");
        if (observationSequence <= 0) {
            throw new IllegalArgumentException("observationSequence must be positive");
        }
        this.observationSequence = observationSequence;
        this.issuedAt = Objects.requireNonNull(issuedAt, "issuedAt");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
        if (!this.expiresAt.isAfter(this.issuedAt)) {
            throw new IllegalArgumentException("expiresAt must be after issuedAt");
        }
        this.signedFrameSha256 = BackendAuthorityPin.sha256(
                signedFrameSha256, "signedFrameSha256");
        this.grantId = Objects.requireNonNull(grantId, "grantId");
        this.grantCommitmentSha256 = BackendAuthorityPin.sha256(
                grantCommitmentSha256, "grantCommitmentSha256");
        this.lifecycleCommitmentSha256 = BackendAuthorityPin.sha256(
                lifecycleCommitmentSha256, "lifecycleCommitmentSha256");
        this.backendKeyIdSha256 = BackendAuthorityPin.sha256(
                backendKeyIdSha256, "backendKeyIdSha256");
        this.authorityProfileSha256 = BackendAuthorityPin.sha256(
                authorityProfileSha256, "authorityProfileSha256");
        this.providerEvidenceCommitmentSha256 = BackendAuthorityPin.sha256(
                providerEvidenceCommitmentSha256, "providerEvidenceCommitmentSha256");
    }

    byte[] frame() { return frame.clone(); }
    public UUID attestationId() { return attestationId; }
    public long observationSequence() { return observationSequence; }
    public Instant issuedAt() { return issuedAt; }
    public Instant expiresAt() { return expiresAt; }
    public String signedFrameSha256() { return signedFrameSha256; }
    public String lifecycleCommitmentSha256() { return lifecycleCommitmentSha256; }
    public String backendKeyIdSha256() { return backendKeyIdSha256; }
    public String authorityProfileSha256() { return authorityProfileSha256; }
    /**
     * Content-free commitment to the exact profile plus provider quorum/window evidence signed
     * into this frame. This is intentionally distinct from the static authority profile hash.
     */
    public String providerEvidenceCommitmentSha256() {
        return providerEvidenceCommitmentSha256;
    }

    /**
     * Returns the exact signed frame only after its issuance record has been forced and verified.
     *
     * <p>This accessor deliberately lives on the durable capability rather than on the codec's
     * undurable signing result. Platform adapters can therefore transport only a frame whose
     * matching issuance record crossed the journal durability boundary.</p>
     */
    public byte[] frameForTransport() {
        return frame.clone();
    }

    /** True only for the exact verified grant and physical lifecycle signed into this frame. */
    public boolean matches(BackendAuthorityGrantCodec.VerifiedGrant grant) {
        if (grant == null) {
            return false;
        }
        return grantId.equals(grant.grantId())
                && grantCommitmentSha256.equals(grant.commitmentSha256())
                && lifecycleCommitmentSha256.equals(
                AuthorityIssuanceCommitments.lifecycle(grant))
                && !issuedAt.isBefore(grant.issuedAt())
                && !expiresAt.isAfter(grant.expiresAt());
    }
}
