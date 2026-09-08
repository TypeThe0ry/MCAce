package com.ellan.mcace.core.session;

import java.util.UUID;

/** An intent to notify, not proof of platform dispatch or client receipt. */
public record ArtifactTelemetryNotice(UUID playerId, String sessionId, Kind kind) {
    public enum Kind { STALE, RECOVERED }
}
