package com.ellan.mcace.client.ui;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

final class GuiEvidenceChallengeTest {
    @Test
    void normalLaunchAddsNoDisclosure() {
        assertTrue(GuiEvidenceChallenge.disclosure(null).isEmpty());
    }

    @Test
    void displayPreservesEveryChallengeCharacterInOrder() {
        String challenge = "0123456789abcdef".repeat(4);
        var lines = GuiEvidenceChallenge.disclosure(challenge);
        assertEquals(challenge, String.join("", lines.subList(1, lines.size())));
        assertTrue(lines.subList(1, lines.size()).stream().allMatch(line -> line.length() == 16));
        assertThrows(UnsupportedOperationException.class, () -> lines.add("extra"));
    }

    @Test
    void malformedConfiguredChallengesFailClosed() {
        for (String value : new String[]{"", "a".repeat(63), "a".repeat(65),
                "A".repeat(64), "a".repeat(63) + "\n", "<script>"}) {
            assertThrows(IllegalArgumentException.class, () -> GuiEvidenceChallenge.disclosure(value));
        }
    }
}
