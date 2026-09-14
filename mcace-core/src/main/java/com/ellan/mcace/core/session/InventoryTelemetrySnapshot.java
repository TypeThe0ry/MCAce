package com.ellan.mcace.core.session;

import java.util.Objects;

/** Atomic server-receipt summary of client claims; no artifact identities or content. */
public record InventoryTelemetrySnapshot(ArtifactTelemetrySnapshot telemetry,
        int loadedMods, int selectedResourcePacks, int selectedShaderPacks) {
    public InventoryTelemetrySnapshot {
        Objects.requireNonNull(telemetry, "telemetry");
        if (loadedMods < 0 || selectedResourcePacks < 0 || selectedShaderPacks < 0) {
            throw new IllegalArgumentException("inventory counts must be nonnegative");
        }
    }
}
