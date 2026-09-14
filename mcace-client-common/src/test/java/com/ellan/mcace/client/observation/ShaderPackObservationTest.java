package com.ellan.mcace.client.observation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

final class ShaderPackObservationTest {
    @Test
    void normalizesProviderValuesAndDropsDisabledSentinels() {
        assertEquals(
                List.of("BSL", "Complementary"),
                ShaderPackObservation.normalizePackNames(
                        List.of(" Complementary ", "BSL", "", "(off)", "OFF", "Complementary")));
    }

    @Test
    void absentOptionalProviderIsFailClosed() {
        assertTrue(ShaderPackObservation.currentEnabledShaderPackIds().isEmpty());
    }
}
