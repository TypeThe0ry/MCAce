package com.ellan.mcace.core.context;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.BackendContextUpdate;
import com.google.protobuf.InvalidProtocolBufferException;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/** Strict, unsigned codec for source-authenticated Paper/Folia context plugin messages. */
public final class BackendContextCodec {
    public static final int SCHEMA_VERSION = 1;
    public static final Duration MAX_REPORT_AGE = Duration.ofMinutes(2);
    private static final int MAX_FIELD_CHARS = 128;
    private static final Pattern WORLD_ID = Pattern.compile("[a-z0-9_.-]+:[a-z0-9/._-]+");
    private static final Set<String> GAME_MODES = Set.of("adventure", "creative", "spectator", "survival");

    private final Clock clock;

    public BackendContextCodec(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public byte[] encode(BackendContextReport report) throws BackendContextException {
        Objects.requireNonNull(report, "report");
        validate(report, clock.instant());
        byte[] encoded = BackendContextUpdate.newBuilder()
                .setSchemaVersion(SCHEMA_VERSION)
                .setPlayerUuid(report.playerId().toString())
                .setAdmissionTransportSequence(report.admissionTransportSequence())
                .setReportSequence(report.reportSequence())
                .setWorldId(report.worldId())
                .setGameMode(report.gameMode())
                .setObservedAtEpochMs(report.observedAt().toEpochMilli())
                .build()
                .toByteArray();
        if (encoded.length == 0 || encoded.length > ProtocolConstants.MAX_BACKEND_CONTEXT_FRAME_BYTES) {
            throw new BackendContextException("backend context frame is outside the size limit");
        }
        return encoded;
    }

    public BackendContextReport decode(byte[] encoded) throws BackendContextException {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length == 0 || encoded.length > ProtocolConstants.MAX_BACKEND_CONTEXT_FRAME_BYTES) {
            throw new BackendContextException("backend context frame is outside the size limit");
        }
        BackendContextUpdate update;
        try {
            update = BackendContextUpdate.parseFrom(encoded);
        } catch (InvalidProtocolBufferException exception) {
            throw new BackendContextException("malformed backend context frame", exception);
        }
        if (update.getSchemaVersion() != SCHEMA_VERSION) {
            throw new BackendContextException("unsupported backend context schema");
        }
        UUID playerId = canonicalUuid(update.getPlayerUuid());
        Instant observedAt;
        try {
            observedAt = Instant.ofEpochMilli(update.getObservedAtEpochMs());
        } catch (DateTimeException exception) {
            throw new BackendContextException("invalid backend context timestamp", exception);
        }
        BackendContextReport report;
        try {
            report = new BackendContextReport(
                    playerId,
                    update.getAdmissionTransportSequence(),
                    update.getReportSequence(),
                    update.getWorldId(),
                    update.getGameMode().toLowerCase(Locale.ROOT),
                    observedAt);
        } catch (IllegalArgumentException exception) {
            throw new BackendContextException("invalid backend context sequence", exception);
        }
        validate(report, clock.instant());
        return report;
    }

    private static void validate(BackendContextReport report, Instant now) throws BackendContextException {
        if (!WORLD_ID.matcher(report.worldId()).matches() || report.worldId().length() > MAX_FIELD_CHARS) {
            throw new BackendContextException("invalid backend world id");
        }
        if (report.gameMode().length() > MAX_FIELD_CHARS || !GAME_MODES.contains(report.gameMode())) {
            throw new BackendContextException("invalid backend game mode");
        }
        Instant oldest;
        Instant newest;
        try {
            oldest = now.minus(MAX_REPORT_AGE);
            newest = now.plus(ProtocolConstants.DEFAULT_CLOCK_SKEW);
        } catch (DateTimeException | ArithmeticException exception) {
            throw new BackendContextException("invalid backend context time window", exception);
        }
        if (report.observedAt().isBefore(oldest) || report.observedAt().isAfter(newest)) {
            throw new BackendContextException("backend context report is stale or from the future");
        }
    }

    private static UUID canonicalUuid(String value) throws BackendContextException {
        try {
            UUID result = UUID.fromString(value);
            if (!result.toString().equals(value)) {
                throw new BackendContextException("backend context UUID is not canonical");
            }
            return result;
        } catch (IllegalArgumentException exception) {
            throw new BackendContextException("invalid backend context UUID", exception);
        }
    }
}
