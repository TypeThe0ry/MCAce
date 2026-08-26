package com.ellan.mcace.paper.behavior;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

final class ProviderEventIdentityCacheTest {
    @Test
    void repeatsIdentityForTheSameObjectAndSeparatesDistinctEqualObjects() {
        ProviderEventIdentityCache cache = new ProviderEventIdentityCache();
        String first = new String("equal-provider-event");
        String equalButDistinct = new String("equal-provider-event");

        assertEquals(cache.identityFor(first), cache.identityFor(first));
        assertNotEquals(cache.identityFor(first), cache.identityFor(equalButDistinct));
    }
}
