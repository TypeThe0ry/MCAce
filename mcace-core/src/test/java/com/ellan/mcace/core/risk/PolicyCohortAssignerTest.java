package com.ellan.mcace.core.risk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import org.junit.jupiter.api.Test;

final class PolicyCohortAssignerTest {
    @Test
    void assignmentIsStableBoundedAndPolicySpecific() {
        UUID player = UUID.fromString("11111111-2222-3333-4444-555555555555");
        UUID firstPolicy = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        UUID secondPolicy = UUID.fromString("01234567-89ab-cdef-0123-456789abcdef");
        int bucket = PolicyCohortAssigner.bucket(player, firstPolicy);
        assertEquals(bucket, PolicyCohortAssigner.bucket(player, firstPolicy));
        assertTrue(bucket >= 0 && bucket < 10_000);
        assertNotEquals(bucket, PolicyCohortAssigner.bucket(player, secondPolicy));
    }
}
