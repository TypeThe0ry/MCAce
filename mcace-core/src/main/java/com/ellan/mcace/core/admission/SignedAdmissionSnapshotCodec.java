package com.ellan.mcace.core.admission;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.EnvelopeCodec;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.AdmissionDecision;
import com.ellan.mcace.protocol.generated.AdmissionReason;
import com.ellan.mcace.protocol.generated.AdmissionUpdate;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.RiskClassification;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import com.ellan.mcace.sdk.RiskBand;
import com.ellan.mcace.sdk.RiskReason;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Signs and verifies short-lived Velocity-to-backend admission snapshots. */
public final class SignedAdmissionSnapshotCodec {
    public static final Duration MAX_TRANSPORT_TTL = Duration.ofSeconds(30);
    private static final int MAX_REASONS = 64;
    private static final int MAX_FIELD_CHARS = 128;

    private final Clock clock;
    private final EnvelopeCodec envelopeCodec;

    public SignedAdmissionSnapshotCodec(Clock clock, SecureRandom secureRandom) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.envelopeCodec = new EnvelopeCodec(
                clock,
                Objects.requireNonNull(secureRandom, "secureRandom"),
                ProtocolConstants.MAX_PAYLOAD_BYTES,
                ProtocolConstants.DEFAULT_CLOCK_SKEW);
    }

    public byte[] sign(
            PlayerSecuritySnapshot snapshot,
            Duration transportTtl,
            long transportSequence,
            PrivateKey privateKey) throws EnvelopeException {
        return signWithExpiry(snapshot, transportTtl, transportSequence, privateKey).encodedFrame();
    }

    /** Signs one transport frame and returns the exact expiry encoded into its signed payload. */
    public SignedAdmissionSnapshot signWithExpiry(
            PlayerSecuritySnapshot snapshot,
            Duration transportTtl,
            long transportSequence,
            PrivateKey privateKey) throws EnvelopeException {
        Objects.requireNonNull(snapshot, "snapshot");
        Objects.requireNonNull(transportTtl, "transportTtl");
        Objects.requireNonNull(privateKey, "privateKey");
        if (transportTtl.isZero() || transportTtl.isNegative()
                || transportTtl.compareTo(MAX_TRANSPORT_TTL) > 0) {
            throw new EnvelopeException("admission transport TTL is outside the allowed range");
        }
        if (transportSequence <= 0) {
            throw new EnvelopeException("admission transport sequence must be positive");
        }
        Instant now = clock.instant();
        validateSnapshot(snapshot, now.plus(ProtocolConstants.DEFAULT_CLOCK_SKEW));

        Instant expiresAt;
        try {
            // The protobuf wire field is epoch milliseconds. Return that same canonical instant
            // so proxy-side backend bindings cannot outlive the signed frame by a fractional
            // millisecond that was discarded during serialization.
            expiresAt = Instant.ofEpochMilli(now.plus(transportTtl).toEpochMilli());
        } catch (DateTimeException | ArithmeticException exception) {
            throw new EnvelopeException("invalid admission transport expiry", exception);
        }
        AdmissionUpdate.Builder update = AdmissionUpdate.newBuilder()
                .setPlayerUuid(snapshot.playerId().toString())
                .setTrustLevel(snapshot.trustLevel())
                .setAdmissionStatus(encodeAdmission(snapshot.admissionStatus()))
                .setRiskScore(snapshot.riskScore())
                .setRiskBand(encodeRiskBand(snapshot.riskBand()))
                .setPolicyVersion(snapshot.policyVersion())
                .setEvaluatedAtEpochMs(snapshot.evaluatedAt().toEpochMilli())
                .setExpiresAtEpochMs(expiresAt.toEpochMilli())
                .setTransportSequence(transportSequence);
        for (RiskReason reason : snapshot.reasons()) {
            update.addReasons(AdmissionReason.newBuilder()
                    .setCode(reason.code())
                    .setWeight(reason.weight())
                    .setSource(reason.source())
                    .setObservedAtEpochMs(reason.observedAt().toEpochMilli())
                    .setCorroborated(reason.corroborated()));
        }
        byte[] encodedFrame = envelopeCodec.sign(
                PacketType.ADMISSION_UPDATE,
                snapshot.playerId().toString(),
                update.build().toByteArray(),
                privateKey).toByteArray();
        return new SignedAdmissionSnapshot(encodedFrame, expiresAt);
    }

    public record SignedAdmissionSnapshot(byte[] encodedFrame, Instant expiresAt) {
        public SignedAdmissionSnapshot {
            encodedFrame = Objects.requireNonNull(encodedFrame, "encodedFrame").clone();
            Objects.requireNonNull(expiresAt, "expiresAt");
        }

        @Override
        public byte[] encodedFrame() {
            return encodedFrame.clone();
        }
    }

    public VerifiedAdmissionSnapshot verify(
            byte[] encoded,
            UUID carrierPlayerId,
            PublicKey publicKey,
            NonceReplayGuard replayGuard) throws EnvelopeException {
        Objects.requireNonNull(encoded, "encoded");
        Objects.requireNonNull(carrierPlayerId, "carrierPlayerId");
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(replayGuard, "replayGuard");
        SignedEnvelope envelope = envelopeCodec.parse(encoded);
        if (envelope.getHeader().getPacketType() != PacketType.ADMISSION_UPDATE) {
            throw new EnvelopeException("unexpected backend admission packet type");
        }
        if (!carrierPlayerId.toString().equals(envelope.getHeader().getSessionId())) {
            throw new EnvelopeException("admission envelope is not bound to the carrier player");
        }
        envelopeCodec.verify(envelope, publicKey, replayGuard);

        AdmissionUpdate update;
        try {
            update = AdmissionUpdate.parseFrom(envelope.getPayload());
        } catch (InvalidProtocolBufferException exception) {
            throw new EnvelopeException("malformed admission update", exception);
        }
        UUID assertedPlayer = parseCanonicalUuid(update.getPlayerUuid());
        if (!carrierPlayerId.equals(assertedPlayer)) {
            throw new EnvelopeException("admission update player does not match the carrier player");
        }
        if (update.getTransportSequence() <= 0) {
            throw new EnvelopeException("invalid admission transport sequence");
        }
        if (update.getReasonsCount() > MAX_REASONS) {
            throw new EnvelopeException("too many admission reasons");
        }

        Instant issuedAt = instant(envelope.getHeader().getTimestampEpochMs(), "envelope timestamp");
        Instant evaluatedAt = instant(update.getEvaluatedAtEpochMs(), "evaluation timestamp");
        Instant expiresAt = instant(update.getExpiresAtEpochMs(), "admission expiry");
        Instant maximumExpiry;
        Instant maximumEvaluation;
        try {
            maximumExpiry = issuedAt.plus(MAX_TRANSPORT_TTL);
            maximumEvaluation = issuedAt.plus(ProtocolConstants.DEFAULT_CLOCK_SKEW);
        } catch (DateTimeException | ArithmeticException exception) {
            throw new EnvelopeException("invalid admission time range", exception);
        }
        if (!expiresAt.isAfter(issuedAt) || expiresAt.isAfter(maximumExpiry)
                || !clock.instant().isBefore(expiresAt)) {
            throw new EnvelopeException("admission update is expired or exceeds its maximum TTL");
        }

        List<RiskReason> reasons = new ArrayList<>(update.getReasonsCount());
        int reasonScore = 0;
        for (AdmissionReason reason : update.getReasonsList()) {
            validateField(reason.getCode(), "reason code");
            validateField(reason.getSource(), "reason source");
            Instant observedAt = instant(reason.getObservedAtEpochMs(), "reason timestamp");
            if (observedAt.isAfter(maximumEvaluation)) {
                throw new EnvelopeException("admission reason timestamp is in the future");
            }
            try {
                reasonScore = Math.addExact(reasonScore, reason.getWeight());
            } catch (ArithmeticException exception) {
                throw new EnvelopeException("admission reason score overflow", exception);
            }
            reasons.add(new RiskReason(
                    reason.getCode(),
                    reason.getWeight(),
                    reason.getSource(),
                    observedAt,
                    reason.getCorroborated()));
        }
        if (update.getRiskScore() < 0 || reasonScore != update.getRiskScore()) {
            throw new EnvelopeException("admission risk score does not match its reasons");
        }
        validateField(update.getPolicyVersion(), "policy version");
        if (evaluatedAt.isAfter(maximumEvaluation)) {
            throw new EnvelopeException("admission evaluation timestamp is in the future");
        }

        AdmissionStatus admissionStatus = decodeAdmission(update.getAdmissionStatus());
        TrustLevel trustLevel = update.getTrustLevel();
        if (trustLevel == TrustLevel.UNRECOGNIZED
                || (admissionStatus == AdmissionStatus.VERIFIED && trustLevel == TrustLevel.UNKNOWN)) {
            throw new EnvelopeException("inconsistent admission trust state");
        }
        PlayerSecuritySnapshot snapshot = new PlayerSecuritySnapshot(
                assertedPlayer,
                trustLevel,
                admissionStatus,
                update.getRiskScore(),
                decodeRiskBand(update.getRiskBand()),
                update.getPolicyVersion(),
                evaluatedAt,
                reasons);
        return new VerifiedAdmissionSnapshot(snapshot, expiresAt, update.getTransportSequence());
    }

    private static void validateSnapshot(PlayerSecuritySnapshot snapshot, Instant maximumEvaluation)
            throws EnvelopeException {
        validateField(snapshot.policyVersion(), "policy version");
        if (snapshot.reasons().size() > MAX_REASONS || snapshot.evaluatedAt().isAfter(maximumEvaluation)) {
            throw new EnvelopeException("snapshot is outside admission transport limits");
        }
        if (snapshot.trustLevel() == TrustLevel.UNRECOGNIZED
                || (snapshot.admissionStatus() == AdmissionStatus.VERIFIED
                && snapshot.trustLevel() == TrustLevel.UNKNOWN)) {
            throw new EnvelopeException("snapshot has an inconsistent admission trust state");
        }
        int score = 0;
        for (RiskReason reason : snapshot.reasons()) {
            validateField(reason.code(), "reason code");
            validateField(reason.source(), "reason source");
            if (reason.observedAt().isAfter(maximumEvaluation)) {
                throw new EnvelopeException("snapshot reason timestamp is in the future");
            }
            try {
                score = Math.addExact(score, reason.weight());
            } catch (ArithmeticException exception) {
                throw new EnvelopeException("snapshot reason score overflow", exception);
            }
        }
        if (score != snapshot.riskScore()) {
            throw new EnvelopeException("snapshot risk score does not match its reasons");
        }
    }

    private static UUID parseCanonicalUuid(String value) throws EnvelopeException {
        try {
            UUID uuid = UUID.fromString(value);
            if (!uuid.toString().equals(value)) {
                throw new EnvelopeException("admission update UUID is not canonical");
            }
            return uuid;
        } catch (IllegalArgumentException exception) {
            throw new EnvelopeException("invalid admission player UUID", exception);
        }
    }

    private static Instant instant(long epochMillis, String field) throws EnvelopeException {
        try {
            return Instant.ofEpochMilli(epochMillis);
        } catch (DateTimeException exception) {
            throw new EnvelopeException("invalid " + field, exception);
        }
    }

    private static void validateField(String value, String field) throws EnvelopeException {
        if (value == null || value.isBlank() || value.length() > MAX_FIELD_CHARS) {
            throw new EnvelopeException(field + " is blank or too long");
        }
    }

    private static AdmissionDecision encodeAdmission(AdmissionStatus status) {
        return switch (status) {
            case CONNECTING -> AdmissionDecision.ADMISSION_CONNECTING;
            case VERIFYING -> AdmissionDecision.ADMISSION_VERIFYING;
            case VERIFIED -> AdmissionDecision.ADMISSION_VERIFIED;
            case LIMITED -> AdmissionDecision.ADMISSION_LIMITED;
            case BLOCKED -> AdmissionDecision.ADMISSION_BLOCKED;
        };
    }

    private static AdmissionStatus decodeAdmission(AdmissionDecision status) throws EnvelopeException {
        return switch (status) {
            case ADMISSION_CONNECTING -> AdmissionStatus.CONNECTING;
            case ADMISSION_VERIFYING -> AdmissionStatus.VERIFYING;
            case ADMISSION_VERIFIED -> AdmissionStatus.VERIFIED;
            case ADMISSION_LIMITED -> AdmissionStatus.LIMITED;
            case ADMISSION_BLOCKED -> AdmissionStatus.BLOCKED;
            default -> throw new EnvelopeException("unspecified admission status");
        };
    }

    private static RiskClassification encodeRiskBand(RiskBand band) {
        return switch (band) {
            case NORMAL -> RiskClassification.RISK_NORMAL;
            case WATCH -> RiskClassification.RISK_WATCH;
            case RESTRICTED -> RiskClassification.RISK_RESTRICTED;
            case INVESTIGATION -> RiskClassification.RISK_INVESTIGATION;
        };
    }

    private static RiskBand decodeRiskBand(RiskClassification band) throws EnvelopeException {
        return switch (band) {
            case RISK_NORMAL -> RiskBand.NORMAL;
            case RISK_WATCH -> RiskBand.WATCH;
            case RISK_RESTRICTED -> RiskBand.RESTRICTED;
            case RISK_INVESTIGATION -> RiskBand.INVESTIGATION;
            default -> throw new EnvelopeException("unspecified risk classification");
        };
    }

    public record VerifiedAdmissionSnapshot(
            PlayerSecuritySnapshot snapshot,
            Instant expiresAt,
            long transportSequence) {
        public VerifiedAdmissionSnapshot {
            Objects.requireNonNull(snapshot, "snapshot");
            Objects.requireNonNull(expiresAt, "expiresAt");
            if (transportSequence <= 0) {
                throw new IllegalArgumentException("transportSequence must be positive");
            }
        }
    }
}
