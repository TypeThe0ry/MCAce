package com.ellan.mcace.core.session;

import java.time.Duration;
import java.util.Objects;

/** Optional operational notice policy; never a cheat or admission policy. */
public record ArtifactTelemetryNoticePolicy(boolean enabled, Duration maximumAge) {
    public ArtifactTelemetryNoticePolicy {
        Objects.requireNonNull(maximumAge, "maximumAge");
        if (maximumAge.compareTo(com.ellan.mcace.protocol.ProtocolConstants.ARTIFACT_OBSERVATION_INTERVAL) <= 0
                || maximumAge.compareTo(Duration.ofHours(1)) > 0) {
            throw new IllegalArgumentException("telemetry notice age must exceed the refresh interval and be at most one hour");
        }
    }
    public static ArtifactTelemetryNoticePolicy disabled() {
        return new ArtifactTelemetryNoticePolicy(false,
                com.ellan.mcace.protocol.ProtocolConstants.ARTIFACT_OBSERVATION_INTERVAL.multipliedBy(3));
    }
}
