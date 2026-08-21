package com.ellan.mcace.core.authority;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.BackendAuthorityGrant;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/** Pure protocol library for short-lived proxy-to-backend authority grants. */
public final class BackendAuthorityGrantCodec {
    private final Clock clock;
    private final SecureRandom secureRandom;
    private final EnvelopeCodec envelopeCodec;

    public BackendAuthorityGrantCodec(Clock clock, SecureRandom secureRandom) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
        this.envelopeCodec = new EnvelopeCodec(clock, secureRandom,
                ProtocolConstants.MAX_BACKEND_AUTHORITY_FRAME_BYTES,
                ProtocolConstants.DEFAULT_CLOCK_SKEW);
    }

    public IssuedGrant issue(GrantRequest request, PrivateKey proxyPrivateKey)
            throws AuthorityProtocolException {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(proxyPrivateKey, "proxyPrivateKey");
        Instant issuedAt = Instant.ofEpochMilli(clock.millis());
        Instant expiresAt = AuthorityProtocolSupport.add(issuedAt, request.lifetime(), "grant expiry");
        UUID grantId = randomUuid();
        byte[] challenge = randomBytes(AuthorityProtocolSupport.CHALLENGE_BYTES);
        BackendAuthorityGrant grant = BackendAuthorityGrant.newBuilder()
                .setSchemaVersion(ProtocolConstants.BACKEND_AUTHORITY_SCHEMA_VERSION)
                .setGrantId(grantId.toString())
                .setProxyInstanceId(request.proxyInstanceId())
                .setBackendInstanceId(request.backendInstanceId())
                .setPlayerUuid(request.playerId().toString())
                .setAuthenticatedSessionId(request.authenticatedSessionId())
                .setPhysicalLoginBinding(ByteString.copyFrom(request.physicalLoginBinding()))
                .setAdmissionTransportSequence(request.admissionTransportSequence())
                .setGrantSequence(request.grantSequence())
                .setIssuedAtEpochMs(issuedAt.toEpochMilli())
                .setExpiresAtEpochMs(expiresAt.toEpochMilli())
                .setChallenge(ByteString.copyFrom(challenge))
                .build();
        String commitment = AuthorityProtocolSupport.grantCommitment(grant);
        try {
            byte[] frame = envelopeCodec.sign(PacketType.BACKEND_AUTHORITY_GRANT,
                    request.authenticatedSessionId(), grant.toByteArray(), proxyPrivateKey).toByteArray();
            AuthorityProtocolSupport.requireFrameSize(frame);
            return new IssuedGrant(frame, grantId, challenge, issuedAt, expiresAt, commitment);
        } catch (EnvelopeException exception) {
            throw new AuthorityProtocolException("failed to sign backend authority grant", exception);
        }
    }

    /**
     * Verifies a grant for exact current lifecycle facts.
     *
     * <p>The shared envelope verifier consumes a valid signed nonce before payload semantic
     * validation. A semantically invalid but correctly signed grant can therefore consume only
     * its own bounded replay slot; callers must use the existing per-session quota. The caller
     * must compare and commit the returned sequence under its player lifecycle lock.</p>
     */
    public VerifiedGrant verify(
            byte[] encoded,
            String expectedProxyInstanceId,
            String expectedBackendInstanceId,
            UUID carrierPlayerId,
            String expectedAuthenticatedSessionId,
            byte[] expectedPhysicalLoginBinding,
            long expectedAdmissionTransportSequence,
            long previousGrantSequence,
            PublicKey proxyPublicKey,
            NonceReplayGuard replayGuard) throws AuthorityProtocolException {
        AuthorityProtocolSupport.requireFrameSize(encoded);
        byte[] frame = encoded.clone();
        BackendAuthorityPin.bounded(expectedProxyInstanceId, "expectedProxyInstanceId");
        BackendAuthorityPin.bounded(expectedBackendInstanceId, "expectedBackendInstanceId");
        Objects.requireNonNull(carrierPlayerId, "carrierPlayerId");
        BackendAuthorityPin.bounded(expectedAuthenticatedSessionId, "expectedAuthenticatedSessionId");
        byte[] expectedBinding = AuthorityProtocolSupport.requireLength(
                expectedPhysicalLoginBinding, AuthorityProtocolSupport.BINDING_BYTES,
                "expectedPhysicalLoginBinding");
        if (expectedAdmissionTransportSequence <= 0 || previousGrantSequence < 0) {
            throw new IllegalArgumentException("invalid expected grant sequence state");
        }
        Objects.requireNonNull(proxyPublicKey, "proxyPublicKey");
        Objects.requireNonNull(replayGuard, "replayGuard");

        SignedEnvelope envelope;
        try {
            envelope = envelopeCodec.parse(frame);
            AuthorityProtocolSupport.requireCanonicalEncoding(
                    frame, envelope, "backend authority grant envelope");
            if (envelope.getHeader().getPacketType() != PacketType.BACKEND_AUTHORITY_GRANT
                    || !envelope.getHeader().getSessionId().equals(expectedAuthenticatedSessionId)) {
                throw new AuthorityProtocolException("backend authority grant envelope binding mismatch");
            }
            envelopeCodec.verify(envelope, proxyPublicKey, replayGuard);
        } catch (EnvelopeException exception) {
            throw new AuthorityProtocolException("invalid backend authority grant envelope", exception);
        }

        BackendAuthorityGrant grant;
        try {
            grant = BackendAuthorityGrant.parseFrom(envelope.getPayload());
        } catch (InvalidProtocolBufferException exception) {
            throw new AuthorityProtocolException("malformed backend authority grant", exception);
        }
        AuthorityProtocolSupport.requireCanonicalEncoding(
                envelope.getPayload().toByteArray(), grant, "backend authority grant");
        AuthorityProtocolSupport.rejectUnknown(grant, "backend authority grant");
        if (grant.getSchemaVersion() != ProtocolConstants.BACKEND_AUTHORITY_SCHEMA_VERSION) {
            throw new AuthorityProtocolException("unsupported backend authority grant schema");
        }
        UUID grantId = AuthorityProtocolSupport.canonicalUuid(grant.getGrantId(), "grant id");
        UUID playerId = AuthorityProtocolSupport.canonicalUuid(grant.getPlayerUuid(), "grant player id");
        if (!expectedProxyInstanceId.equals(grant.getProxyInstanceId())
                || !expectedBackendInstanceId.equals(grant.getBackendInstanceId())
                || !carrierPlayerId.equals(playerId)
                || !expectedAuthenticatedSessionId.equals(grant.getAuthenticatedSessionId())
                || grant.getAdmissionTransportSequence() != expectedAdmissionTransportSequence
                || grant.getGrantSequence() <= previousGrantSequence) {
            throw new AuthorityProtocolException("backend authority grant lifecycle binding mismatch");
        }
        byte[] binding = grant.getPhysicalLoginBinding().toByteArray();
        byte[] challenge = grant.getChallenge().toByteArray();
        AuthorityProtocolSupport.requireExactBytes(binding, expectedBinding, "physical login binding");
        if (binding.length != AuthorityProtocolSupport.BINDING_BYTES
                || challenge.length != AuthorityProtocolSupport.CHALLENGE_BYTES) {
            throw new AuthorityProtocolException("invalid backend authority grant byte length");
        }
        Instant issuedAt = AuthorityProtocolSupport.instant(grant.getIssuedAtEpochMs(), "grant issued time");
        Instant expiresAt = AuthorityProtocolSupport.instant(grant.getExpiresAtEpochMs(), "grant expiry");
        Instant maximumExpiry = AuthorityProtocolSupport.add(
                issuedAt, ProtocolConstants.MAX_BACKEND_AUTHORITY_TTL, "maximum grant expiry");
        Instant verificationNow = clock.instant();
        if (!expiresAt.isAfter(issuedAt) || expiresAt.isAfter(maximumExpiry)
                || !verificationNow.isBefore(expiresAt)
                || AuthorityProtocolSupport.absoluteDeltaMillis(
                        verificationNow.toEpochMilli(), issuedAt.toEpochMilli())
                > ProtocolConstants.DEFAULT_CLOCK_SKEW.toMillis()
                || AuthorityProtocolSupport.absoluteDeltaMillis(
                        envelope.getHeader().getTimestampEpochMs(), issuedAt.toEpochMilli())
                > ProtocolConstants.DEFAULT_CLOCK_SKEW.toMillis()) {
            throw new AuthorityProtocolException("backend authority grant is expired or outside time bounds");
        }
        return new VerifiedGrant(
                grantId, grant.getProxyInstanceId(), grant.getBackendInstanceId(), playerId,
                grant.getAuthenticatedSessionId(), binding, grant.getAdmissionTransportSequence(),
                grant.getGrantSequence(), issuedAt, expiresAt, challenge,
                AuthorityProtocolSupport.grantCommitment(grant));
    }

    private UUID randomUuid() {
        byte[] value = randomBytes(16);
        value[6] = (byte) ((value[6] & 0x0f) | 0x40);
        value[8] = (byte) ((value[8] & 0x3f) | 0x80);
        ByteBuffer buffer = ByteBuffer.wrap(value);
        return new UUID(buffer.getLong(), buffer.getLong());
    }

    private byte[] randomBytes(int length) {
        byte[] value = new byte[length];
        secureRandom.nextBytes(value);
        return value;
    }

    public record GrantRequest(
            String proxyInstanceId,
            String backendInstanceId,
            UUID playerId,
            String authenticatedSessionId,
            byte[] physicalLoginBinding,
            long admissionTransportSequence,
            long grantSequence,
            Duration lifetime) {
        public GrantRequest {
            proxyInstanceId = BackendAuthorityPin.bounded(proxyInstanceId, "proxyInstanceId");
            backendInstanceId = BackendAuthorityPin.bounded(backendInstanceId, "backendInstanceId");
            Objects.requireNonNull(playerId, "playerId");
            authenticatedSessionId = BackendAuthorityPin.bounded(
                    authenticatedSessionId, "authenticatedSessionId");
            physicalLoginBinding = AuthorityProtocolSupport.requireLength(
                    physicalLoginBinding, AuthorityProtocolSupport.BINDING_BYTES, "physicalLoginBinding");
            if (admissionTransportSequence <= 0 || grantSequence <= 0) {
                throw new IllegalArgumentException("authority grant sequences must be positive");
            }
            Objects.requireNonNull(lifetime, "lifetime");
            if (lifetime.isZero() || lifetime.isNegative()
                    || lifetime.compareTo(ProtocolConstants.MAX_BACKEND_AUTHORITY_TTL) > 0
                    || lifetime.toMillis() <= 0L
                    || !Duration.ofMillis(lifetime.toMillis()).equals(lifetime)) {
                throw new IllegalArgumentException("authority grant lifetime is outside protocol limits");
            }
        }

        @Override
        public byte[] physicalLoginBinding() {
            return physicalLoginBinding.clone();
        }
    }

    /** Issuer-side metadata; this is deliberately not a receiver verification token. */
    public record IssuedGrant(
            byte[] frame,
            UUID grantId,
            byte[] challenge,
            Instant issuedAt,
            Instant expiresAt,
            String commitmentSha256) {
        public IssuedGrant {
            frame = Objects.requireNonNull(frame, "frame").clone();
            Objects.requireNonNull(grantId, "grantId");
            challenge = AuthorityProtocolSupport.requireLength(
                    challenge, AuthorityProtocolSupport.CHALLENGE_BYTES, "challenge");
            Objects.requireNonNull(issuedAt, "issuedAt");
            Objects.requireNonNull(expiresAt, "expiresAt");
            commitmentSha256 = BackendAuthorityPin.sha256(
                    commitmentSha256, "commitmentSha256");
        }

        @Override
        public byte[] frame() {
            return frame.clone();
        }

        @Override
        public byte[] challenge() {
            return challenge.clone();
        }
    }

    public static final class VerifiedGrant {
        private final UUID grantId;
        private final String proxyInstanceId;
        private final String backendInstanceId;
        private final UUID playerId;
        private final String authenticatedSessionId;
        private final byte[] physicalLoginBinding;
        private final long admissionTransportSequence;
        private final long grantSequence;
        private final Instant issuedAt;
        private final Instant expiresAt;
        private final byte[] challenge;
        private final String commitmentSha256;

        VerifiedGrant(
                UUID grantId,
                String proxyInstanceId,
                String backendInstanceId,
                UUID playerId,
                String authenticatedSessionId,
                byte[] physicalLoginBinding,
                long admissionTransportSequence,
                long grantSequence,
                Instant issuedAt,
                Instant expiresAt,
                byte[] challenge,
                String commitmentSha256) {
            this.grantId = Objects.requireNonNull(grantId, "grantId");
            this.proxyInstanceId = BackendAuthorityPin.bounded(proxyInstanceId, "proxyInstanceId");
            this.backendInstanceId = BackendAuthorityPin.bounded(backendInstanceId, "backendInstanceId");
            this.playerId = Objects.requireNonNull(playerId, "playerId");
            this.authenticatedSessionId = BackendAuthorityPin.bounded(
                    authenticatedSessionId, "authenticatedSessionId");
            this.physicalLoginBinding = AuthorityProtocolSupport.requireLength(
                    physicalLoginBinding, AuthorityProtocolSupport.BINDING_BYTES, "physicalLoginBinding");
            this.challenge = AuthorityProtocolSupport.requireLength(
                    challenge, AuthorityProtocolSupport.CHALLENGE_BYTES, "challenge");
            if (admissionTransportSequence <= 0 || grantSequence <= 0) {
                throw new IllegalArgumentException("authority grant sequences must be positive");
            }
            this.admissionTransportSequence = admissionTransportSequence;
            this.grantSequence = grantSequence;
            this.issuedAt = Objects.requireNonNull(issuedAt, "issuedAt");
            this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
            this.commitmentSha256 = BackendAuthorityPin.sha256(
                    commitmentSha256, "commitmentSha256");
        }

        public UUID grantId() { return grantId; }
        public String proxyInstanceId() { return proxyInstanceId; }
        public String backendInstanceId() { return backendInstanceId; }
        public UUID playerId() { return playerId; }
        public String authenticatedSessionId() { return authenticatedSessionId; }
        public byte[] physicalLoginBinding() { return physicalLoginBinding.clone(); }
        public long admissionTransportSequence() { return admissionTransportSequence; }
        public long grantSequence() { return grantSequence; }
        public Instant issuedAt() { return issuedAt; }
        public Instant expiresAt() { return expiresAt; }
        public byte[] challenge() { return challenge.clone(); }
        public String commitmentSha256() { return commitmentSha256; }
    }
}
