package com.ellan.mcace.core.authority;

import com.ellan.mcace.protocol.ProtocolConstants;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Narrow output of cryptographic backend verification.
 *
 * <p>It deliberately has no enforcement metadata and is not wired to the trusted
 * authorization runtime. Its package-private constructor means only this package's
 * verifier can create the token.</p>
 */
public final class VerifiedServerAuthorityObservation {
    private final UUID attestationId;
    private final String registeredBackend;
    private final String backendInstanceId;
    private final String backendKeyIdSha256;
    private final UUID playerId;
    private final String authenticatedSessionId;
    private final UUID grantId;
    private final String grantCommitmentSha256;
    private final byte[] physicalLoginBinding;
    private final long admissionTransportSequence;
    private final long observationSequence;
    private final Instant observedAt;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private final String authorityProfileSha256;
    private final String signedFrameSha256;
    private final List<ProviderSummary> providers;
    private final String providerEvidenceCommitmentSha256;

    VerifiedServerAuthorityObservation(
            UUID attestationId,
            String registeredBackend,
            String backendInstanceId,
            String backendKeyIdSha256,
            UUID playerId,
            String authenticatedSessionId,
            UUID grantId,
            String grantCommitmentSha256,
            byte[] physicalLoginBinding,
            long admissionTransportSequence,
            long observationSequence,
            Instant observedAt,
            Instant issuedAt,
            Instant expiresAt,
            String authorityProfileSha256,
            String signedFrameSha256,
            List<ProviderSummary> providers) {
        this.attestationId = Objects.requireNonNull(attestationId, "attestationId");
        this.registeredBackend = BackendAuthorityPin.bounded(registeredBackend, "registeredBackend");
        this.backendInstanceId = BackendAuthorityPin.bounded(backendInstanceId, "backendInstanceId");
        this.backendKeyIdSha256 = BackendAuthorityPin.sha256(
                backendKeyIdSha256, "backendKeyIdSha256");
        this.playerId = Objects.requireNonNull(playerId, "playerId");
        this.authenticatedSessionId = BackendAuthorityPin.bounded(
                authenticatedSessionId, "authenticatedSessionId");
        this.grantId = Objects.requireNonNull(grantId, "grantId");
        this.grantCommitmentSha256 = BackendAuthorityPin.sha256(
                grantCommitmentSha256, "grantCommitmentSha256");
        this.physicalLoginBinding = Objects.requireNonNull(
                physicalLoginBinding, "physicalLoginBinding").clone();
        if (physicalLoginBinding.length != 32 || admissionTransportSequence <= 0 || observationSequence <= 0) {
            throw new IllegalArgumentException("invalid authority lifecycle binding or sequence");
        }
        this.admissionTransportSequence = admissionTransportSequence;
        this.observationSequence = observationSequence;
        this.observedAt = Objects.requireNonNull(observedAt, "observedAt");
        this.issuedAt = Objects.requireNonNull(issuedAt, "issuedAt");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
        if (observedAt.isAfter(issuedAt) || !expiresAt.isAfter(issuedAt)
                || Duration.between(issuedAt, expiresAt)
                .compareTo(ProtocolConstants.MAX_BACKEND_AUTHORITY_TTL) > 0) {
            throw new IllegalArgumentException("invalid authority observation time range");
        }
        this.authorityProfileSha256 = BackendAuthorityPin.sha256(
                authorityProfileSha256, "authorityProfileSha256");
        this.signedFrameSha256 = BackendAuthorityPin.sha256(
                signedFrameSha256, "signedFrameSha256");
        this.providers = List.copyOf(Objects.requireNonNull(providers, "providers"));
        if (this.providers.size() < 2
                || this.providers.size() > ProtocolConstants.MAX_BACKEND_AUTHORITY_PROVIDERS) {
            throw new IllegalArgumentException("authority provider count is outside bounds");
        }
        Set<String> domains = new HashSet<>();
        Set<String> providerIds = new HashSet<>();
        for (ProviderSummary provider : this.providers) {
            if (!domains.add(provider.trustDomainId())
                    || !providerIds.add(provider.providerId())
                    || provider.windowEndedAt().isAfter(observedAt)
                    || provider.windowEndedAt().isBefore(
                    observedAt.minus(ProtocolConstants.MAX_BACKEND_AUTHORITY_OBSERVATION_AGE))) {
                throw new IllegalArgumentException("authority providers are not independent or current");
            }
        }
        this.providerEvidenceCommitmentSha256 =
                AuthorityIssuanceCommitments.providers(this);
    }

    public UUID attestationId() { return attestationId; }
    public String registeredBackend() { return registeredBackend; }
    public String backendInstanceId() { return backendInstanceId; }
    public String backendKeyIdSha256() { return backendKeyIdSha256; }
    public UUID playerId() { return playerId; }
    public String authenticatedSessionId() { return authenticatedSessionId; }
    public UUID grantId() { return grantId; }
    public String grantCommitmentSha256() { return grantCommitmentSha256; }
    public byte[] physicalLoginBinding() {
        return physicalLoginBinding.clone();
    }
    public long admissionTransportSequence() { return admissionTransportSequence; }
    public long observationSequence() { return observationSequence; }
    public Instant observedAt() { return observedAt; }
    public Instant issuedAt() { return issuedAt; }
    public Instant expiresAt() { return expiresAt; }
    public String authorityProfileSha256() { return authorityProfileSha256; }
    public String signedFrameSha256() { return signedFrameSha256; }
    public List<ProviderSummary> providers() { return providers; }
    /** Exact content-free commitment to the verified provider evidence carried by this frame. */
    public String providerEvidenceCommitmentSha256() {
        return providerEvidenceCommitmentSha256;
    }

    public record ProviderSummary(
            String trustDomainId,
            String providerId,
            String providerVersion,
            String stableCheckFamily,
            int threshold,
            int observedCount,
            Instant windowStartedAt,
            Instant windowEndedAt) {
        public ProviderSummary {
            trustDomainId = BackendAuthorityPin.bounded(trustDomainId, "trustDomainId");
            providerId = BackendAuthorityPin.bounded(providerId, "providerId");
            providerVersion = BackendAuthorityPin.bounded(providerVersion, "providerVersion");
            stableCheckFamily = BackendAuthorityPin.bounded(stableCheckFamily, "stableCheckFamily");
            if (threshold <= 0 || observedCount < threshold) {
                throw new IllegalArgumentException("provider threshold is invalid or unmet");
            }
            Objects.requireNonNull(windowStartedAt, "windowStartedAt");
            Objects.requireNonNull(windowEndedAt, "windowEndedAt");
            if (windowEndedAt.isBefore(windowStartedAt)
                    || Duration.between(windowStartedAt, windowEndedAt)
                    .compareTo(ProtocolConstants.MAX_BACKEND_AUTHORITY_OBSERVATION_AGE) > 0) {
                throw new IllegalArgumentException("provider window is outside authority bounds");
            }
        }
    }
}
