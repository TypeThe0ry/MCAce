package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

final class VelocityBackendReadyBarrierTest {
    private static final UUID PLAYER = UUID.fromString("00000000-0000-0000-0000-000000000003");

    @Test
    void onlyPostConnectMakesTheCurrentGenerationReady() {
        VelocityBackendReadyBarrier barrier = new VelocityBackendReadyBarrier();
        long first = barrier.beginConnection(PLAYER);
        assertFalse(barrier.isReady(PLAYER, first));
        assertTrue(barrier.isReady(PLAYER, barrier.markReady(PLAYER)));
        long second = barrier.beginConnection(PLAYER);
        assertFalse(barrier.isReady(PLAYER, first));
        assertFalse(barrier.isReady(PLAYER, second));
        assertTrue(barrier.isReady(PLAYER, barrier.markReady(PLAYER)));
    }

    @Test
    void concurrentLifecycleUpdatesRemainSynchronized() throws Exception {
        VelocityBackendReadyBarrier barrier = new VelocityBackendReadyBarrier();
        CountDownLatch started = new CountDownLatch(1);
        Thread updater = new Thread(() -> {
            started.countDown();
            for (int index = 0; index < 1_000; index++) {
                barrier.beginConnection(PLAYER);
                barrier.markReady(PLAYER);
            }
        });
        updater.start();
        assertTrue(started.await(1, TimeUnit.SECONDS));
        for (int index = 0; index < 1_000; index++) barrier.isReady(PLAYER);
        updater.join(1_000);
        assertFalse(updater.isAlive());
    }

    @Test
    void olderPostConnectCannotMakeNewerGenerationReady() {
        VelocityBackendReadyBarrier barrier = new VelocityBackendReadyBarrier();
        long generationA = barrier.beginConnection(PLAYER);
        long generationB = barrier.beginConnection(PLAYER);

        assertEquals(generationA, barrier.markReady(PLAYER));
        assertFalse(barrier.isReady(PLAYER, generationB));
        assertEquals(generationB, barrier.markReady(PLAYER));
        assertTrue(barrier.isReady(PLAYER, generationB));
    }
}
