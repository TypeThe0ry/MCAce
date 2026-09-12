package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.*;
import com.ellan.mcace.core.session.ArtifactTelemetrySnapshot;
import com.ellan.mcace.core.session.InventoryTelemetrySnapshot;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class InventoryTelemetryQueryTest {
    @Test void validatesBeforeLookupAndDistinguishesMissingFromEmpty() {
        var calls = new AtomicInteger();
        var query = new InventoryTelemetryQuery((id, age) -> { calls.incrementAndGet(); return Optional.empty(); });
        for (String[] args : new String[][] {{}, {"bad"}, {"1-1-1-1-1"}, {UUID.randomUUID().toString(), "extra"}}) {
            assertEquals(InventoryTelemetryQuery.USAGE, query.execute(args));
        }
        assertEquals(0, calls.get());
        assertEquals("MCAce: inventory state=UNAVAILABLE", query.execute(new String[] {UUID.randomUUID().toString()}));
        assertEquals(1, calls.get());
    }

    @Test void rendersCountsWithFreshnessAndNoSessionIdentity() {
        UUID player = UUID.randomUUID();
        Instant now = Instant.parse("2026-09-08T00:00:00Z");
        var query = new InventoryTelemetryQuery((id, age) -> {
            assertEquals(player, id);
            return Optional.of(new InventoryTelemetrySnapshot(new ArtifactTelemetrySnapshot(
                    "private-session", 2, now, now.plus(age), age), 17, 3, 0));
        });
        String result = query.execute(new String[] {player.toString()});
        assertTrue(result.contains("state=STALE updateSequence=2 loadedMods=17 selectedResourcePacks=3 selectedShaderPacks=0"));
        assertTrue(result.contains("client claims; not cheat-free proof"));
        assertFalse(result.contains(player.toString()));
        assertFalse(result.contains("private-session"));
    }
}
