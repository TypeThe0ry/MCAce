package com.ellan.mcace.core.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class BoundedAsyncFederationAuditSinkTest {
    @Test
    void saturationRejectsImmediatelyWithoutRunningDelegateOnCallerThread() throws Exception {
        CountDownLatch workerEntered = new CountDownLatch(1);
        CountDownLatch releaseWorker = new CountDownLatch(1);
        String callerThread = Thread.currentThread().getName();
        try (BoundedAsyncFederationAuditSink sink = new BoundedAsyncFederationAuditSink(record -> {
            assertFalse(Thread.currentThread().getName().equals(callerThread));
            workerEntered.countDown();
            await(releaseWorker);
        }, 1, "mcace-federation-audit-test")) {
            assertTrue(sink.offer(record()));
            assertTrue(workerEntered.await(5, TimeUnit.SECONDS));
            assertTrue(sink.offer(record()));

            long started = System.nanoTime();
            assertFalse(sink.offer(record()));
            assertTrue(Duration.ofNanos(System.nanoTime() - started).compareTo(Duration.ofSeconds(1)) < 0);
            assertEquals(1L, sink.status().saturated());
            assertEquals(1, sink.status().queued());
            releaseWorker.countDown();
        }
    }

    @Test
    void handlerFailureIsCountedAndWorkerContinuesWithLaterRecords() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch successfulRecord = new CountDownLatch(1);
        try (BoundedAsyncFederationAuditSink sink = new BoundedAsyncFederationAuditSink(record -> {
            if (calls.incrementAndGet() == 1) {
                throw new IllegalStateException("injected audit failure");
            }
            successfulRecord.countDown();
        }, 4, "mcace-federation-audit-recovery-test")) {
            assertTrue(sink.offer(record()));
            assertTrue(sink.offer(record()));
            assertTrue(successfulRecord.await(5, TimeUnit.SECONDS));
            awaitStatus(sink, 1L, 1L);
            assertEquals(2L, sink.status().accepted());
            assertTrue(sink.status().workerAlive());
        }
    }

    @Test
    void closeDrainsAcceptedRecordsAndRejectsFutureOffers() throws Exception {
        CountDownLatch processed = new CountDownLatch(2);
        BoundedAsyncFederationAuditSink sink = new BoundedAsyncFederationAuditSink(
                ignored -> processed.countDown(), 2, "mcace-federation-audit-close-test");
        assertTrue(sink.offer(record()));
        assertTrue(sink.offer(record()));
        sink.close(Duration.ofSeconds(5));

        assertTrue(processed.await(1, TimeUnit.SECONDS));
        assertTrue(sink.status().closed());
        assertFalse(sink.status().workerAlive());
        assertFalse(sink.offer(record()));
        assertEquals(1L, sink.status().rejectedAfterClose());
    }

    private static FederationAuditRecord record() {
        return new FederationAuditRecord(
                Instant.parse("2026-08-09T00:00:00Z"),
                FederationAuditEvent.PRESENTATION_REJECTED,
                FederationAuditOutcome.INVALID_PRESENTATION,
                "test-operator",
                UUID.randomUUID(),
                "source-network",
                "target-network",
                Optional.empty(),
                Optional.empty());
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) {
                throw new AssertionError("timed out waiting for audit test latch");
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AssertionError("audit test interrupted", exception);
        }
    }

    private static void awaitStatus(
            BoundedAsyncFederationAuditSink sink,
            long expectedProcessed,
            long expectedFailures) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            FederationAuditQueueStatus status = sink.status();
            if (status.processed() == expectedProcessed
                    && status.handlerFailures() == expectedFailures) {
                return;
            }
            Thread.sleep(10L);
        }
        FederationAuditQueueStatus status = sink.status();
        assertEquals(expectedProcessed, status.processed());
        assertEquals(expectedFailures, status.handlerFailures());
    }
}
