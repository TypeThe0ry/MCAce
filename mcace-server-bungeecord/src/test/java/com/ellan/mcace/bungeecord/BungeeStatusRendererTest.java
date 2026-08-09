package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.ellan.mcace.core.proxy.ProxyPolicyRefreshStatus;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import com.ellan.mcace.sdk.RiskBand;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class BungeeStatusRendererTest {
    @Test
    void rendersOnlyOperationalStatus() {
        PlayerSecuritySnapshot snapshot = new PlayerSecuritySnapshot(
                UUID.fromString("47b580f8-3e43-4b5d-8f03-8fe6acacde6a"),
                TrustLevel.VERIFIED,
                AdmissionStatus.VERIFIED,
                15,
                RiskBand.NORMAL,
                "policy-1",
                Instant.parse("2026-08-08T00:00:00Z"),
                List.of());

        assertEquals("MCAce: Player trust=VERIFIED admission=VERIFIED risk=15 band=NORMAL",
                BungeeStatusRenderer.snapshot("Player", snapshot));
    }

    @Test
    void rendersDispositionStatusWithoutPolicyMaterial() {
        assertEquals("MCAce: disposition status=ACTIVE sequence=42 (observational; no automatic punishment)",
                BungeeStatusRenderer.disposition(new BungeeDispositionStatus(
                        ProxyPolicyRefreshStatus.ACTIVE, java.util.Optional.of(42L))));
    }
}
