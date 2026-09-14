package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.session.ArtifactTelemetrySnapshot;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.BiFunction;

/** Shared, content-free administrator query. Its window is diagnostic, never an enforcement setting. */
public final class ArtifactTelemetryQuery {
    public static final int DEFAULT_WINDOW_SECONDS = Math.toIntExact(
            com.ellan.mcace.protocol.ProtocolConstants.ARTIFACT_OBSERVATION_INTERVAL.multipliedBy(3).toSeconds());
    public static final String USAGE = "Usage: /mcaceobservation freshness <uuid> [1-3600 seconds; default "
            + DEFAULT_WINDOW_SECONDS + "]";
    private final BiFunction<UUID, Duration, Optional<ArtifactTelemetrySnapshot>> snapshots;

    public ArtifactTelemetryQuery(BiFunction<UUID, Duration, Optional<ArtifactTelemetrySnapshot>> snapshots) {
        this.snapshots = Objects.requireNonNull(snapshots, "snapshots");
    }

    public String execute(String[] arguments) {
        if (arguments.length < 1 || arguments.length > 2) return USAGE;
        final UUID player;
        final int seconds;
        try {
            player = UUID.fromString(arguments[0]);
            if (!player.toString().equalsIgnoreCase(arguments[0])) return USAGE;
            seconds = arguments.length == 2 ? Integer.parseInt(arguments[1]) : DEFAULT_WINDOW_SECONDS;
            if (seconds < 1 || seconds > 3600) return USAGE;
        } catch (IllegalArgumentException exception) { return USAGE; }
        var result = snapshots.apply(player, Duration.ofSeconds(seconds));
        String prefix = "MCAce: telemetry diagnosticWindowSeconds=" + seconds;
        if (result.isEmpty()) return prefix + " state=UNAVAILABLE (no current manifest or unsupported bridge)";
        var snapshot = result.orElseThrow();
        return prefix + " state=" + snapshot.freshness() + " updateSequence=" + snapshot.updateSequence()
                + " receivedAt=" + snapshot.receivedAt() + " evaluatedAt=" + snapshot.evaluatedAt()
                + " (client claims; not cheat-free proof or an execution receipt)";
    }
}
