package com.ellan.mcace.paper.behavior;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class GrimEventTokensTest {
    @Test
    void identicalFlagsAtTheSameViolationLevelGetDistinctProviderEventIds() {
        GrimBehaviorIntegration.EventTokens tokens = new GrimBehaviorIntegration.EventTokens();
        String player = UUID.randomUUID().toString();
        Set<String> ids = new HashSet<>();
        for (int index = 0; index < 1000; index++) {
            ids.add(BehaviorAlert.providerEventIdSha256("grim", player, "2.3.72", "reach", "Reach",
                    Double.toHexString(3.0D), "false", tokens.next()));
        }
        assertEquals(1000, ids.size());
    }

    @Test
    void separateIntegrationsDoNotShareTokens() {
        assertNotEquals(new GrimBehaviorIntegration.EventTokens().next(),
                new GrimBehaviorIntegration.EventTokens().next());
    }
}
