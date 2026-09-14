package com.ellan.mcace.core.session;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Duration;
import org.junit.jupiter.api.Test;

final class ArtifactTelemetryNoticePolicyTest {
    @Test void rejectsWindowsThatConflictWithCadenceOrAreUnbounded() {
        assertFalse(ArtifactTelemetryNoticePolicy.disabled().enabled());
        assertThrows(IllegalArgumentException.class,
                () -> new ArtifactTelemetryNoticePolicy(true, Duration.ofMinutes(5)));
        assertThrows(IllegalArgumentException.class,
                () -> new ArtifactTelemetryNoticePolicy(true, Duration.ofHours(2)));
        assertDoesNotThrow(() -> new ArtifactTelemetryNoticePolicy(true, Duration.ofSeconds(301)));
    }
}
