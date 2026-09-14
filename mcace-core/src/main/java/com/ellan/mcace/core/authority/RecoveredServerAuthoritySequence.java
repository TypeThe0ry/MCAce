package com.ellan.mcace.core.authority;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** Durable sequence recovery bound to one exact verified backend-authority grant. */
public final class RecoveredServerAuthoritySequence {
    private final UUID grantId;
    private final String grantCommitmentSha256;
    private final String lifecycleCommitmentSha256;
    private final String backendKeyIdSha256;
    private final long lastSequence;
    private final Optional<Instant> lastObservedAt;
    private final Optional<Instant> lastIssuedAt;

    RecoveredServerAuthoritySequence(
            BackendAuthorityGrantCodec.VerifiedGrant grant,
            String lifecycleCommitmentSha256,
            String backendKeyIdSha256,
            ServerAuthorityIssuanceRecovery recovery) {
        Objects.requireNonNull(grant, "grant");
        Objects.requireNonNull(recovery, "recovery");
        this.grantId = grant.grantId();
        this.grantCommitmentSha256 = BackendAuthorityPin.sha256(
                grant.commitmentSha256(), "grantCommitmentSha256");
        this.lifecycleCommitmentSha256 = BackendAuthorityPin.sha256(
                lifecycleCommitmentSha256, "lifecycleCommitmentSha256");
        this.backendKeyIdSha256 = BackendAuthorityPin.sha256(
                backendKeyIdSha256, "backendKeyIdSha256");
        this.lastSequence = recovery.lastSequence();
        this.lastObservedAt = recovery.lastObservedAt();
        this.lastIssuedAt = recovery.lastIssuedAt();
        if (!matches(grant)) {
            throw new IllegalArgumentException("recovered sequence does not match its grant");
        }
    }

    public long lastSequence() {
        return lastSequence;
    }

    /** Last durably accepted provider observation time, when at least one record exists. */
    public Optional<Instant> lastObservedAt() {
        return lastObservedAt;
    }

    /** Last durable authority-frame issuance time, when at least one record exists. */
    public Optional<Instant> lastIssuedAt() {
        return lastIssuedAt;
    }

    public String lifecycleCommitmentSha256() {
        return lifecycleCommitmentSha256;
    }

    public String backendKeyIdSha256() {
        return backendKeyIdSha256;
    }

    /** True only for the exact grant and physical lifecycle used during recovery. */
    public boolean matches(BackendAuthorityGrantCodec.VerifiedGrant grant) {
        if (grant == null) {
            return false;
        }
        return grantId.equals(grant.grantId())
                && grantCommitmentSha256.equals(grant.commitmentSha256())
                && lifecycleCommitmentSha256.equals(
                AuthorityIssuanceCommitments.lifecycle(grant));
    }
}
