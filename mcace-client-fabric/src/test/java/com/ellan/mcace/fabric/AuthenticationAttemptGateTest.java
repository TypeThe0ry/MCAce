package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

final class AuthenticationAttemptGateTest {
    @Test
    void supersededChallengeCannotReuseThePreviousAuthenticationAttempt() {
        AuthenticationAttemptGate gate = new AuthenticationAttemptGate();
        long first = gate.begin();
        long second = gate.begin();

        assertFalse(gate.isActive(first));
        assertTrue(gate.isActive(second));
        assertTrue(gate.activeAttempt() == second);
        gate.cancel();
        assertFalse(gate.isActive(second));
        assertTrue(gate.activeAttempt() == 0L);
    }
}
