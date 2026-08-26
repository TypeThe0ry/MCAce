package com.ellan.mcace.core.authority;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.ServerAuthorityObservation;
import com.ellan.mcace.protocol.generated.ServerAuthorityProviderSummary;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Pure signing and verification library for content-free backend authority observations.
 *
 * <p>Production adapters may register this protocol only through the default-disabled MONITOR
 * runtime. Its verified output is deliberately narrower than an {@code ArtifactObservation} and
 * is not itself a disposition authorization.</p>
 */
public final class ServerAuthorityObservationCodec {
    private final Clock clock;
    private final SecureRandom secureRandom;
    private final EnvelopeCodec envelopeCodec;

    public ServerAuthorityObservationCodec(Clock clock, SecureRandom secureRandom) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
        this.envelopeCodec = new EnvelopeCodec(clock, secureRandom,
                ProtocolConstants.MAX_BACKEND_AUTHORITY_FRAME_BYTES,
                ProtocolConstants.DEFAULT_CLOCK_SKEW);
    }

    /**
     * Creates an unsigned-lifecycle frame for this package's verifier tests and durable issuer.
     *
     * <p>This primitive is deliberately package-private: production callers must use
     * {@link DurableServerAuthorityIssuer}, which cannot create a durable capability until its
     * issuance record has been forced to durable storage.</p>
     */
    IssuedObservation sign(ObservationRequest request, PrivateKey backendPrivateKey)
            throws AuthorityProtocolException {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(backendPrivateKey, "backendPrivateKey");
        Instant issuedAt = Instant.ofEpochMilli(clock.millis());
        if (request.observedAt().isAfter(issuedAt)
                || request.observedAt().isBefore(AuthorityProtocolSupport.add(
                        issuedAt, ProtocolConstants.MAX_BACKEND_AUTHORITY_OBSERVATION_AGE.negated(),
                        "minimum observation time"))) {
            throw new AuthorityProtocolException("authority observation time is outside protocol limits");
        }
        Instant expiresAt = AuthorityProtocolSupport.add(issuedAt, request.lifetime(), "authority expiry");
        UUID attestationId = randomUuid();
        ServerAuthorityObservation.Builder observation = ServerAuthorityObservation.newBuilder()
                .setSchemaVersion(ProtocolConstants.BACKEND_AUTHORITY_SCHEMA_VERSION)
                .setAttestationId(attestationId.toString())
                .setBackendInstanceId(request.backendInstanceId())
                .setBackendKeyIdSha256(ByteString.copyFrom(
                        AuthorityProtocolSupport.unhex(request.backendKeyIdSha256(), "backendKeyIdSha256")))
                .setPlayerUuid(request.playerId().toString())
                .setAuthenticatedSessionId(request.authenticatedSessionId())
                .setGrantId(request.grantId().toString())
                .setGrantCommitmentSha256(ByteString.copyFrom(AuthorityProtocolSupport.unhex(
                        request.grantCommitmentSha256(), "grantCommitmentSha256")))
                .setPhysicalLoginBinding(ByteString.copyFrom(request.physicalLoginBinding()))
                .setAdmissionTransportSequence(request.admissionTransportSequence())
                .setObservationSequence(request.observationSequence())
                .setObservedAtEpochMs(request.observedAt().toEpochMilli())
                .setIssuedAtEpochMs(issuedAt.toEpochMilli())
                .setExpiresAtEpochMs(expiresAt.toEpochMilli())
                .setAuthorityProfileSha256(ByteString.copyFrom(AuthorityProtocolSupport.unhex(
                        request.authorityProfileSha256(), "authorityProfileSha256")));
        request.providers().forEach(provider -> observation.addProviders(provider.toProto()));
        try {
            byte[] frame = envelopeCodec.sign(PacketType.SERVER_AUTHORITY_OBSERVATION,
                    request.authenticatedSessionId(), observation.build().toByteArray(),
                    backendPrivateKey).toByteArray();
            AuthorityProtocolSupport.requireFrameSize(frame);
            return new IssuedObservation(frame, attestationId, issuedAt, expiresAt);
        } catch (EnvelopeException exception) {
            throw new AuthorityProtocolException("failed to sign server authority observation", exception);
        }
    }

    /**
     * Verifies a frame against proxy-derived lifecycle facts and an exact backend pin.
     *
     * <p>The envelope nonce is consumed after a valid signature but before payload semantics are
     * checked. A signed semantic rejection can consume only its own bounded per-session replay
     * slot; the frame cannot become valid by retrying it. The caller must hold its player
     * lifecycle lock while reading the prior accepted snapshot, invoking this method, and
     * committing the returned observation sequence and times. {@link Optional#empty()} is the
     * explicit initial state for a new physical-login binding.</p>
     */
    public VerifiedServerAuthorityObservation verify(
            byte[] encoded,
            String carryingRegisteredBackend,
            UUID carrierPlayerId,
            String currentAuthenticatedSessionId,
            byte[] currentPhysicalLoginBinding,
            long currentAdmissionTransportSequence,
            BackendAuthorityGrantCodec.VerifiedGrant currentGrant,
            Optional<PriorAcceptedObservation> priorAccepted,
            BackendAuthorityRegistry registry,
            NonceReplayGuard replayGuard) throws AuthorityProtocolException {
        AuthorityProtocolSupport.requireFrameSize(encoded);
        byte[] frame = encoded.clone();
        String registeredBackend = BackendAuthorityPin.bounded(
                carryingRegisteredBackend, "carryingRegisteredBackend");
        Objects.requireNonNull(carrierPlayerId, "carrierPlayerId");
        String sessionId = BackendAuthorityPin.bounded(
                currentAuthenticatedSessionId, "currentAuthenticatedSessionId");
        Objects.requireNonNull(currentGrant, "currentGrant");
        byte[] expectedGrantCommitment = AuthorityProtocolSupport.unhex(
                currentGrant.commitmentSha256(), "currentGrantCommitmentSha256");
        byte[] expectedBinding = AuthorityProtocolSupport.requireLength(
                currentPhysicalLoginBinding, AuthorityProtocolSupport.BINDING_BYTES,
                "currentPhysicalLoginBinding");
        if (currentAdmissionTransportSequence <= 0) {
            throw new IllegalArgumentException("invalid current authority sequence state");
        }
        Objects.requireNonNull(priorAccepted, "priorAccepted");
        Objects.requireNonNull(registry, "registry");
        Objects.requireNonNull(replayGuard, "replayGuard");
        Instant verificationNow = clock.instant();
        if (!carrierPlayerId.equals(currentGrant.playerId())
                || !sessionId.equals(currentGrant.authenticatedSessionId())
                || currentAdmissionTransportSequence != currentGrant.admissionTransportSequence()
                || !java.security.MessageDigest.isEqual(
                expectedBinding, currentGrant.physicalLoginBinding())
                || !verificationNow.isBefore(currentGrant.expiresAt())) {
            throw new AuthorityProtocolException("current backend authority grant is stale or mismatched");
        }
        BackendAuthorityPin pin = registry.pinForRegisteredBackend(registeredBackend)
                .orElseThrow(() -> new AuthorityProtocolException("backend authority is disabled or unpinned"));
        if (!pin.backendInstanceId().equals(currentGrant.backendInstanceId())) {
            throw new AuthorityProtocolException("backend authority grant targets another backend instance");
        }

        SignedEnvelope envelope;
        try {
            envelope = envelopeCodec.parse(frame);
            AuthorityProtocolSupport.requireCanonicalEncoding(
                    frame, envelope, "server authority observation envelope");
            if (envelope.getHeader().getPacketType() != PacketType.SERVER_AUTHORITY_OBSERVATION
                    || !envelope.getHeader().getSessionId().equals(sessionId)) {
                throw new AuthorityProtocolException("server authority envelope binding mismatch");
            }
            envelopeCodec.verify(envelope, pin.publicKey(), replayGuard);
        } catch (EnvelopeException exception) {
            throw new AuthorityProtocolException("invalid server authority envelope", exception);
        }

        ServerAuthorityObservation observation;
        try {
            observation = ServerAuthorityObservation.parseFrom(envelope.getPayload());
        } catch (InvalidProtocolBufferException exception) {
            throw new AuthorityProtocolException("malformed server authority observation", exception);
        }
        AuthorityProtocolSupport.requireCanonicalEncoding(
                envelope.getPayload().toByteArray(), observation, "server authority observation");
        AuthorityProtocolSupport.rejectUnknown(observation, "server authority observation");
        if (observation.getSchemaVersion() != ProtocolConstants.BACKEND_AUTHORITY_SCHEMA_VERSION) {
            throw new AuthorityProtocolException("unsupported server authority observation schema");
        }
        UUID attestationId = AuthorityProtocolSupport.canonicalUuid(
                observation.getAttestationId(), "attestation id");
        UUID playerId = AuthorityProtocolSupport.canonicalUuid(
                observation.getPlayerUuid(), "authority player id");
        UUID grantId = AuthorityProtocolSupport.canonicalUuid(observation.getGrantId(), "authority grant id");
        String keyId = AuthorityProtocolSupport.hex(
                observation.getBackendKeyIdSha256().toByteArray(), "backend key id");
        String profile = AuthorityProtocolSupport.hex(
                observation.getAuthorityProfileSha256().toByteArray(), "authority profile");
        BackendAuthorityProfile authorityProfile = pin.authorityProfile(profile)
                .orElseThrow(() -> new AuthorityProtocolException(
                        "server authority profile is not operator-pinned"));
        if (!pin.backendInstanceId().equals(observation.getBackendInstanceId())
                || !pin.keyIdSha256().equals(keyId)
                || !carrierPlayerId.equals(playerId)
                || !sessionId.equals(observation.getAuthenticatedSessionId())
                || !currentGrant.grantId().equals(grantId)
                || observation.getAdmissionTransportSequence() != currentAdmissionTransportSequence
                || priorAccepted.map(previous ->
                observation.getObservationSequence() <= previous.observationSequence()).orElse(false)) {
            throw new AuthorityProtocolException("server authority identity or lifecycle binding mismatch");
        }
        byte[] binding = observation.getPhysicalLoginBinding().toByteArray();
        if (binding.length != AuthorityProtocolSupport.BINDING_BYTES) {
            throw new AuthorityProtocolException("invalid physical login binding length");
        }
        AuthorityProtocolSupport.requireExactBytes(binding, expectedBinding, "physical login binding");
        AuthorityProtocolSupport.requireExactBytes(
                observation.getGrantCommitmentSha256().toByteArray(), expectedGrantCommitment,
                "grant commitment");

        Instant observedAt = AuthorityProtocolSupport.instant(
                observation.getObservedAtEpochMs(), "observation time");
        Instant issuedAt = AuthorityProtocolSupport.instant(
                observation.getIssuedAtEpochMs(), "authority issued time");
        Instant expiresAt = AuthorityProtocolSupport.instant(
                observation.getExpiresAtEpochMs(), "authority expiry");
        Instant maximumExpiry = AuthorityProtocolSupport.add(
                issuedAt, ProtocolConstants.MAX_BACKEND_AUTHORITY_TTL, "maximum authority expiry");
        Instant minimumObservation = AuthorityProtocolSupport.add(
                verificationNow, ProtocolConstants.MAX_BACKEND_AUTHORITY_OBSERVATION_AGE.negated(),
                "minimum observation time");
        if (observedAt.isAfter(issuedAt) || observedAt.isBefore(minimumObservation)
                || observedAt.isBefore(currentGrant.issuedAt())
                || issuedAt.isBefore(currentGrant.issuedAt())
                || !expiresAt.isAfter(issuedAt) || expiresAt.isAfter(maximumExpiry)
                || expiresAt.isAfter(currentGrant.expiresAt())
                || !verificationNow.isBefore(expiresAt)
                || AuthorityProtocolSupport.absoluteDeltaMillis(
                        verificationNow.toEpochMilli(), issuedAt.toEpochMilli())
                > ProtocolConstants.DEFAULT_CLOCK_SKEW.toMillis()
                || AuthorityProtocolSupport.absoluteDeltaMillis(
                        envelope.getHeader().getTimestampEpochMs(), issuedAt.toEpochMilli())
                > ProtocolConstants.DEFAULT_CLOCK_SKEW.toMillis()) {
            throw new AuthorityProtocolException("server authority observation is outside time bounds");
        }
        if (priorAccepted.isPresent()) {
            PriorAcceptedObservation previous = priorAccepted.orElseThrow();
            Instant minimumObservedAt = AuthorityProtocolSupport.add(
                    previous.observedAt(), authorityProfile.cooldown(),
                    "minimum cooldown observation time");
            Instant minimumIssuedAt = AuthorityProtocolSupport.add(
                    previous.issuedAt(), authorityProfile.cooldown(),
                    "minimum cooldown issuance time");
            if (observedAt.isBefore(minimumObservedAt) || issuedAt.isBefore(minimumIssuedAt)) {
                throw new AuthorityProtocolException("server authority observation violates profile cooldown");
            }
        }

        if (observation.getProvidersCount() < authorityProfile.requiredIndependentDomains()
                || observation.getProvidersCount() > authorityProfile.providerIds().size()
                || observation.getProvidersCount() > ProtocolConstants.MAX_BACKEND_AUTHORITY_PROVIDERS) {
            throw new AuthorityProtocolException("server authority provider quorum is outside bounds");
        }
        Set<String> domains = new HashSet<>();
        Set<String> providerIds = new HashSet<>();
        List<VerifiedServerAuthorityObservation.ProviderSummary> providers = new ArrayList<>();
        Instant sharedWindowStart = AuthorityProtocolSupport.add(
                observedAt, authorityProfile.maximumProviderWindow().negated(),
                "shared provider window start");
        for (ServerAuthorityProviderSummary provider : observation.getProvidersList()) {
            AuthorityProtocolSupport.rejectUnknown(provider, "server authority provider");
            String domain = bounded(provider.getTrustDomainId(), "trustDomainId");
            String providerId = bounded(provider.getProviderId(), "providerId");
            String version = bounded(provider.getProviderVersion(), "providerVersion");
            String family = bounded(provider.getStableCheckFamily(), "stableCheckFamily");
            BackendAuthorityProfile.ProviderContract contract = authorityProfile.provider(providerId)
                    .orElseThrow(() -> new AuthorityProtocolException(
                            "authority provider is absent from the pinned profile"));
            if (!contract.trustDomainId().equals(domain)
                    || !contract.providerVersion().equals(version)
                    || !contract.stableCheckFamily().equals(family)
                    || contract.threshold() != provider.getThreshold()
                    || !domains.add(domain) || !providerIds.add(providerId)
                    || provider.getThreshold() <= 0
                    || provider.getObservedCount() < provider.getThreshold()) {
                throw new AuthorityProtocolException("invalid or non-independent authority provider");
            }
            Instant windowStart = AuthorityProtocolSupport.instant(
                    provider.getWindowStartedAtEpochMs(), "provider window start");
            Instant windowEnd = AuthorityProtocolSupport.instant(
                    provider.getWindowEndedAtEpochMs(), "provider window end");
            Instant maximumWindowEnd = AuthorityProtocolSupport.add(
                    windowStart, authorityProfile.maximumProviderWindow(),
                    "maximum provider window");
            if (windowEnd.isBefore(windowStart) || windowEnd.isAfter(observedAt)
                    || windowStart.isBefore(currentGrant.issuedAt())
                    || windowStart.isBefore(sharedWindowStart)
                    || windowEnd.isBefore(sharedWindowStart)
                    || windowEnd.isAfter(maximumWindowEnd)) {
                throw new AuthorityProtocolException("provider window is outside authority bounds");
            }
            providers.add(new VerifiedServerAuthorityObservation.ProviderSummary(
                    domain, providerId, version, family, provider.getThreshold(),
                    provider.getObservedCount(), windowStart, windowEnd));
        }
        if (domains.size() < authorityProfile.requiredIndependentDomains()) {
            throw new AuthorityProtocolException("independent authority provider quorum was not met");
        }
        return new VerifiedServerAuthorityObservation(
                attestationId, registeredBackend, pin.backendInstanceId(), keyId, playerId,
                sessionId, grantId, currentGrant.commitmentSha256(), binding,
                observation.getAdmissionTransportSequence(), observation.getObservationSequence(),
                observedAt, issuedAt, expiresAt, profile,
                AuthorityProtocolSupport.sha256(frame), providers);
    }

    private static String bounded(String value, String field) throws AuthorityProtocolException {
        try {
            return BackendAuthorityPin.bounded(value, field);
        } catch (IllegalArgumentException exception) {
            throw new AuthorityProtocolException("invalid " + field, exception);
        }
    }

    private UUID randomUuid() {
        byte[] value = new byte[16];
        secureRandom.nextBytes(value);
        value[6] = (byte) ((value[6] & 0x0f) | 0x40);
        value[8] = (byte) ((value[8] & 0x3f) | 0x80);
        ByteBuffer buffer = ByteBuffer.wrap(value);
        return new UUID(buffer.getLong(), buffer.getLong());
    }

    /**
     * One immutable lifecycle-lock snapshot of the last accepted observation for this binding.
     * Callers must store a new snapshot from the verified result before releasing that lock.
     */
    public record PriorAcceptedObservation(
            long observationSequence, Instant observedAt, Instant issuedAt) {
        public PriorAcceptedObservation {
            if (observationSequence <= 0) {
                throw new IllegalArgumentException("prior observation sequence must be positive");
            }
            Objects.requireNonNull(observedAt, "observedAt");
            Objects.requireNonNull(issuedAt, "issuedAt");
            if (observedAt.isAfter(issuedAt)
                    || !Instant.ofEpochMilli(observedAt.toEpochMilli()).equals(observedAt)
                    || !Instant.ofEpochMilli(issuedAt.toEpochMilli()).equals(issuedAt)) {
                throw new IllegalArgumentException("prior observation times are invalid");
            }
        }

        public static PriorAcceptedObservation from(
                VerifiedServerAuthorityObservation observation) {
            Objects.requireNonNull(observation, "observation");
            return new PriorAcceptedObservation(
                    observation.observationSequence(), observation.observedAt(), observation.issuedAt());
        }
    }

    public record ObservationRequest(
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
            Duration lifetime,
            String authorityProfileSha256,
            List<ProviderInput> providers) {
        public ObservationRequest {
            backendInstanceId = BackendAuthorityPin.bounded(backendInstanceId, "backendInstanceId");
            backendKeyIdSha256 = BackendAuthorityPin.sha256(backendKeyIdSha256, "backendKeyIdSha256");
            Objects.requireNonNull(playerId, "playerId");
            authenticatedSessionId = BackendAuthorityPin.bounded(
                    authenticatedSessionId, "authenticatedSessionId");
            Objects.requireNonNull(grantId, "grantId");
            grantCommitmentSha256 = BackendAuthorityPin.sha256(
                    grantCommitmentSha256, "grantCommitmentSha256");
            physicalLoginBinding = AuthorityProtocolSupport.requireLength(
                    physicalLoginBinding, AuthorityProtocolSupport.BINDING_BYTES,
                    "physicalLoginBinding");
            if (admissionTransportSequence <= 0 || observationSequence <= 0) {
                throw new IllegalArgumentException("authority observation sequences must be positive");
            }
            Objects.requireNonNull(observedAt, "observedAt");
            if (!Instant.ofEpochMilli(observedAt.toEpochMilli()).equals(observedAt)) {
                throw new IllegalArgumentException(
                        "authority observation time must have millisecond precision");
            }
            Objects.requireNonNull(lifetime, "lifetime");
            if (lifetime.isZero() || lifetime.isNegative()
                    || lifetime.compareTo(ProtocolConstants.MAX_BACKEND_AUTHORITY_TTL) > 0
                    || lifetime.toMillis() <= 0L
                    || !Duration.ofMillis(lifetime.toMillis()).equals(lifetime)) {
                throw new IllegalArgumentException("authority lifetime is outside protocol limits");
            }
            authorityProfileSha256 = BackendAuthorityPin.sha256(
                    authorityProfileSha256, "authorityProfileSha256");
            providers = List.copyOf(Objects.requireNonNull(providers, "providers"));
            if (providers.size() < 2
                    || providers.size() > ProtocolConstants.MAX_BACKEND_AUTHORITY_PROVIDERS) {
                throw new IllegalArgumentException("authority provider count is outside bounds");
            }
            Set<String> domains = new HashSet<>();
            Set<String> ids = new HashSet<>();
            providers.forEach(provider -> {
                if (!domains.add(provider.trustDomainId()) || !ids.add(provider.providerId())
                        || provider.windowEndedAt().isAfter(observedAt)
                        || provider.windowEndedAt().isBefore(
                        observedAt.minus(ProtocolConstants.MAX_BACKEND_AUTHORITY_OBSERVATION_AGE))) {
                    throw new IllegalArgumentException("authority providers are not independent");
                }
            });
        }

        @Override public byte[] physicalLoginBinding() { return physicalLoginBinding.clone(); }

        ObservationRequest withObservationSequence(long sequence) {
            return new ObservationRequest(
                    backendInstanceId, backendKeyIdSha256, playerId, authenticatedSessionId,
                    grantId, grantCommitmentSha256, physicalLoginBinding,
                    admissionTransportSequence, sequence, observedAt, lifetime,
                    authorityProfileSha256, providers);
        }
    }

    public record ProviderInput(
            String trustDomainId,
            String providerId,
            String providerVersion,
            String stableCheckFamily,
            int threshold,
            int observedCount,
            Instant windowStartedAt,
            Instant windowEndedAt) {
        public ProviderInput {
            trustDomainId = BackendAuthorityPin.bounded(trustDomainId, "trustDomainId");
            providerId = BackendAuthorityPin.bounded(providerId, "providerId");
            providerVersion = BackendAuthorityPin.bounded(providerVersion, "providerVersion");
            stableCheckFamily = BackendAuthorityPin.bounded(stableCheckFamily, "stableCheckFamily");
            if (threshold <= 0 || observedCount < threshold) {
                throw new IllegalArgumentException("provider threshold is invalid or unmet");
            }
            Objects.requireNonNull(windowStartedAt, "windowStartedAt");
            Objects.requireNonNull(windowEndedAt, "windowEndedAt");
            if (!Instant.ofEpochMilli(windowStartedAt.toEpochMilli()).equals(windowStartedAt)
                    || !Instant.ofEpochMilli(windowEndedAt.toEpochMilli()).equals(windowEndedAt)
                    || windowEndedAt.isBefore(windowStartedAt)
                    || Duration.between(windowStartedAt, windowEndedAt)
                    .compareTo(ProtocolConstants.MAX_BACKEND_AUTHORITY_OBSERVATION_AGE) > 0) {
                throw new IllegalArgumentException("provider window is outside authority bounds");
            }
        }

        private ServerAuthorityProviderSummary toProto() {
            return ServerAuthorityProviderSummary.newBuilder()
                    .setTrustDomainId(trustDomainId)
                    .setProviderId(providerId)
                    .setProviderVersion(providerVersion)
                    .setStableCheckFamily(stableCheckFamily)
                    .setThreshold(threshold)
                    .setObservedCount(observedCount)
                    .setWindowStartedAtEpochMs(windowStartedAt.toEpochMilli())
                    .setWindowEndedAtEpochMs(windowEndedAt.toEpochMilli())
                    .build();
        }
    }

    record IssuedObservation(
            byte[] frame, UUID attestationId, Instant issuedAt, Instant expiresAt) {
        public IssuedObservation {
            frame = Objects.requireNonNull(frame, "frame").clone();
            Objects.requireNonNull(attestationId, "attestationId");
            Objects.requireNonNull(issuedAt, "issuedAt");
            Objects.requireNonNull(expiresAt, "expiresAt");
        }

        @Override public byte[] frame() { return frame.clone(); }
    }
}
