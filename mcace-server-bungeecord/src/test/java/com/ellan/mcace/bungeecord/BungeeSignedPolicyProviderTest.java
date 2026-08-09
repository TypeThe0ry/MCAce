package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class BungeeSignedPolicyProviderTest {
    @Test
    void emitsAValidFabricOnlyPolicyAndReusesItBeforeRenewal() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-08-08T00:00:00Z"), ZoneOffset.UTC);
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        BungeeSignedPolicyProvider provider = new BungeeSignedPolicyProvider(
                new BungeeBridgeConfiguration("test-bungee", "1.21.1", "fabric-build", java.time.Duration.ofSeconds(5)),
                identity,
                clock);

        var first = provider.current();
        var second = provider.current();
        var policy = PolicyDocuments.verify(first, identity.getPublic(), clock, java.time.Duration.ZERO);

        assertSame(first, second);
        assertEquals("test-bungee", policy.getServerId());
        assertEquals(LoaderType.FABRIC, policy.getAllowedLoaders(0));
        assertEquals("fabric-build", policy.getAllowedBuildIds(0));
        assertEquals(4, policy.getIntegrityScopesCount());
    }
}
