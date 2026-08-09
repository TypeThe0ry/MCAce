package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class BungeeBridgeActionTest {
    @Test
    void defensivelyCopiesOutboundFrames() {
        byte[] original = {1, 2, 3};
        BungeeBridgeAction action = new BungeeBridgeAction(List.of(original), Optional.empty(), false);

        original[0] = 99;
        byte[] returned = action.outboundFrames().getFirst();
        returned[1] = 88;

        assertArrayEquals(new byte[] {1, 2, 3}, action.outboundFrames().getFirst());
    }

    @Test
    void noneHasNoFramesOrSnapshot() {
        BungeeBridgeAction action = BungeeBridgeAction.none();

        assertFalse(action.protocolViolation());
        assertFalse(action.snapshot().isPresent());
        assertFalse(action.outboundFrames().iterator().hasNext());
    }
}
