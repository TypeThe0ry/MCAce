package com.ellan.mcace.core.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class BoundedAsyncFederationAuditSinkTest {
    @TempDir Path directory;

    @Test
    void saturationRejectsImmediatelyAndFaultsWithoutRunningDelegateOnCallerThread() throws Exception {
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
            assertTrue(sink.status().faulted());
            assertEquals(0, sink.status().queued());
            assertEquals(1L, sink.status().discardedAfterFault());
            assertFalse(sink.health().available());
            releaseWorker.countDown();
        }
    }

    @Test
    void backgroundHandlerFailureFaultsTheSinkAndRejectsFutureDurableAppends() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch failingRecordEntered = new CountDownLatch(1);
        try (BoundedAsyncFederationAuditSink sink = new BoundedAsyncFederationAuditSink(record -> {
            calls.incrementAndGet();
            failingRecordEntered.countDown();
            throw new IllegalStateException("injected audit failure");
        }, 4, "mcace-federation-audit-recovery-test")) {
            // True is queue admission only and cannot be interpreted as a durable append.
            assertTrue(sink.offer(record()));
            assertTrue(failingRecordEntered.await(5, TimeUnit.SECONDS));
            awaitFaulted(sink);

            assertFalse(sink.health().available());
            assertEquals(0L, sink.status().processed());
            assertEquals(1L, sink.status().handlerFailures());
            assertThrows(IllegalStateException.class, () -> sink.append(record()));
            assertEquals(1, calls.get());
        }
    }

    @Test
    void durableAppendReturnsOnlyAfterTheDelegateCommits() throws Exception {
        CountDownLatch delegateEntered = new CountDownLatch(1);
        CountDownLatch releaseDelegate = new CountDownLatch(1);
        try (BoundedAsyncFederationAuditSink sink = new BoundedAsyncFederationAuditSink(record -> {
            delegateEntered.countDown();
            await(releaseDelegate);
        }, 2, "mcace-federation-audit-durable-test")) {
            java.util.concurrent.CompletableFuture<Void> append =
                    java.util.concurrent.CompletableFuture.runAsync(() -> sink.append(record()));
            assertTrue(delegateEntered.await(5, TimeUnit.SECONDS));
            assertFalse(append.isDone());

            releaseDelegate.countDown();
            append.get(5, TimeUnit.SECONDS);
            assertEquals(1L, sink.status().processed());
            assertTrue(sink.health().available());
        }
    }

    @Test
    void realFileQuotaFailureInBackgroundLatchesAnUnavailableHealthState() throws Exception {
        FileFederationAuditSink file = new FileFederationAuditSink(
                directory.resolve("federation-audit.log"), 1L);
        try (BoundedAsyncFederationAuditSink sink = new BoundedAsyncFederationAuditSink(
                file, 2, "mcace-federation-audit-file-fault-test")) {
            assertTrue(sink.offer(record()));
            awaitFaulted(sink);

            assertFalse(sink.health().available());
            assertEquals(1L, sink.status().handlerFailures());
            assertEquals(0L, sink.status().processed());
            assertThrows(IllegalStateException.class, () -> sink.append(record()));
        }
    }

    @Test
    void commitTimeoutFaultsTheSinkAndUnblocksTheCallerWithoutAuthorizingSuccess() throws Exception {
        CountDownLatch delegateEntered = new CountDownLatch(1);
        CountDownLatch releaseDelegate = new CountDownLatch(1);
        try (BoundedAsyncFederationAuditSink sink = new BoundedAsyncFederationAuditSink(record -> {
            delegateEntered.countDown();
            await(releaseDelegate);
        }, 2, "mcace-federation-audit-timeout-test", Duration.ofMillis(50L))) {
            java.util.concurrent.CompletableFuture<Throwable> result =
                    java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                        try {
                            sink.append(record());
                            return null;
                        } catch (Throwable exception) {
                            return exception;
                        }
                    });
            assertTrue(delegateEntered.await(5, TimeUnit.SECONDS));
            assertTrue(result.get(5, TimeUnit.SECONDS) instanceof IllegalStateException);
            assertTrue(sink.status().faulted());
            assertEquals(1L, sink.status().commitTimeouts());
            assertFalse(sink.health().available());
            releaseDelegate.countDown();
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

    private static void awaitFaulted(BoundedAsyncFederationAuditSink sink) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < deadline) {
            FederationAuditQueueStatus status = sink.status();
            if (status.faulted() && !status.workerAlive()) {
                return;
            }
            Thread.sleep(10L);
        }
        FederationAuditQueueStatus status = sink.status();
        assertTrue(status.faulted());
        assertFalse(status.workerAlive());
    }
}
