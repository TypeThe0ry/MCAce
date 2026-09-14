package com.ellan.mcace.core.session;

import static org.junit.jupiter.api.Assertions.*;

import com.ellan.mcace.protocol.generated.AuthRequest;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class AuthenticatedManifestTest {
    @Test
    void preservesCompatibilityAndSeparatesObservationFromReceiptTime() {
        UUID player = UUID.randomUUID();
        var policy = SecurityPolicy.getDefaultInstance();
        var request = AuthRequest.getDefaultInstance();
        var legacy = new AuthenticatedManifest(player, "s", policy, request, Instant.EPOCH);
        assertEquals(0, legacy.observationSequence());
        assertEquals(Instant.EPOCH, legacy.receivedAt());
        var update = new AuthenticatedManifest(player, "s", policy, request, Instant.EPOCH,
                7, Instant.EPOCH.plusSeconds(2));
        assertEquals(7, update.observationSequence());
        assertEquals(Instant.EPOCH, update.authenticatedAt());
        assertEquals(Instant.EPOCH.plusSeconds(2), update.receivedAt());
        assertThrows(IllegalArgumentException.class, () -> new AuthenticatedManifest(
                player, "s", policy, request, Instant.EPOCH, -1, Instant.EPOCH));
        assertThrows(NullPointerException.class, () -> new AuthenticatedManifest(
                player, "s", policy, request, Instant.EPOCH, 1, null));
    }
}
