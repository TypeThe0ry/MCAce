package com.ellan.mcace.paper.behavior;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import me.frep.vulcan.api.event.VulcanFlagEvent;
import org.junit.jupiter.api.Test;

final class VulcanApiCompatibilityTest {
    @Test
    void recognizesTheNarrowSupportedEventContract() throws Exception {
        VulcanApiCompatibility.Contract contract = VulcanApiCompatibility.inspect(
                VulcanFlagEvent.class.getClassLoader());

        assertEquals(VulcanFlagEvent.class, contract.eventClass());
        assertEquals("getPlayer", contract.playerAccessor());
        assertEquals("getCheck", contract.checkAccessor());
        assertEquals("getCheckName", contract.checkNameAccessor());
        assertEquals("getStableKey", contract.stableCheckAccessor());
        assertEquals("getViolationLevel", contract.eventViolationAccessor());
        assertEquals("getVl", contract.checkViolationAccessor());
    }

    @Test
    void failsClosedWhenNoKnownEventApiExists() {
        ClassLoader empty = new ClassLoader(null) { };
        assertThrows(ReflectiveOperationException.class, () -> VulcanApiCompatibility.inspect(empty));
    }
}