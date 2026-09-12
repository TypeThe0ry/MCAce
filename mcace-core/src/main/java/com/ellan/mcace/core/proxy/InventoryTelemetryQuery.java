package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.session.InventoryTelemetrySnapshot;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.BiFunction;

/** Read-only counts for administrators; does not expose paths, IDs, or file contents. */
public final class InventoryTelemetryQuery {
    public static final String USAGE = "Usage: /mcaceobservation inventory <uuid>";
    private final BiFunction<UUID, Duration, Optional<InventoryTelemetrySnapshot>> snapshots;

    public InventoryTelemetryQuery(BiFunction<UUID, Duration, Optional<InventoryTelemetrySnapshot>> snapshots) {
        this.snapshots = Objects.requireNonNull(snapshots, "snapshots");
    }

    public String execute(String[] arguments) {
        if (arguments.length != 1) return USAGE;
        final UUID player;
        try {
            player = UUID.fromString(arguments[0]);
            if (!player.toString().equalsIgnoreCase(arguments[0])) return USAGE;
        } catch (IllegalArgumentException exception) { return USAGE; }
        var result = snapshots.apply(player, Duration.ofSeconds(ArtifactTelemetryQuery.DEFAULT_WINDOW_SECONDS));
        if (result.isEmpty()) return "MCAce: inventory state=UNAVAILABLE";
        var snapshot = result.orElseThrow();
        return "MCAce: inventory state=" + snapshot.telemetry().freshness()
                + " updateSequence=" + snapshot.telemetry().updateSequence()
                + " loadedMods=" + snapshot.loadedMods()
                + " selectedResourcePacks=" + snapshot.selectedResourcePacks()
                + " selectedShaderPacks=" + snapshot.selectedShaderPacks()
                + " receivedAt=" + snapshot.telemetry().receivedAt()
                + " (client claims; not cheat-free proof or an execution receipt)";
    }
}
