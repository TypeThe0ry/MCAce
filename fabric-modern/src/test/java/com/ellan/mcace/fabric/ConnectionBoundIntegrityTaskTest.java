package com.ellan.mcace.fabric;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.client.integrity.IntegrityScanException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class ConnectionBoundIntegrityTaskTest {
    @Test
    void disconnectCancellationInterruptsWorkAndSuppressesFramePublication() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch interruptObserved = new CountDownLatch(1);
        CountDownLatch finished = new CountDownLatch(1);
        AtomicBoolean interrupted = new AtomicBoolean();
        AtomicInteger publishedFrames = new AtomicInteger();

        try (ConnectionBoundIntegrityTask task = new ConnectionBoundIntegrityTask()) {
            task.submit(cancellation -> {
                started.countDown();
                try {
                    release.await();
                } catch (InterruptedException exception) {
                    interrupted.set(true);
                    interruptObserved.countDown();
                    Thread.currentThread().interrupt();
                }
                try {
                    cancellation.check();
                    publishedFrames.incrementAndGet();
                } catch (IntegrityScanException expectedCancellation) {
                    // A disconnected generation must terminate before any frame publication.
                } finally {
                    finished.countDown();
                }
            });
            assertTrue(started.await(5, TimeUnit.SECONDS));
            task.cancel();
            assertTrue(interruptObserved.await(5, TimeUnit.SECONDS));
            release.countDown();
            assertTrue(finished.await(5, TimeUnit.SECONDS));
        } finally {
            release.countDown();
        }

        assertTrue(interrupted.get(), "cancelling the connection task must interrupt its reader thread");
        assertEquals(0, publishedFrames.get(), "a cancelled generation must publish no frames");
    }

    @Test
    void replacementGenerationCancelsThePreviousTaskBeforePublication() throws Exception {
        CountDownLatch oldStarted = new CountDownLatch(1);
        CountDownLatch oldFinished = new CountDownLatch(1);
        CountDownLatch replacementFinished = new CountDownLatch(1);
        AtomicInteger oldFrames = new AtomicInteger();
        AtomicInteger replacementFrames = new AtomicInteger();

        try (ConnectionBoundIntegrityTask task = new ConnectionBoundIntegrityTask()) {
            task.submit(cancellation -> {
                oldStarted.countDown();
                try {
                    new CountDownLatch(1).await();
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                }
                try {
                    cancellation.check();
                    oldFrames.incrementAndGet();
                } catch (IntegrityScanException expectedCancellation) {
                    // Replacing a connection generation invalidates the previous result.
                } finally {
                    oldFinished.countDown();
                }
            });
            assertTrue(oldStarted.await(5, TimeUnit.SECONDS));
            task.submit(cancellation -> {
                try {
                    cancellation.check();
                    replacementFrames.incrementAndGet();
                } catch (IntegrityScanException unexpected) {
                    throw new AssertionError(unexpected);
                } finally {
                    replacementFinished.countDown();
                }
            });
            assertTrue(oldFinished.await(5, TimeUnit.SECONDS));
            assertTrue(replacementFinished.await(5, TimeUnit.SECONDS));
        }

        assertEquals(0, oldFrames.get());
        assertEquals(1, replacementFrames.get());
    }
}
