package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class PaperServerAuthorityJournalWriterTest {
    @Test
    void workRunsOnOneDedicatedNonCallerThread() throws Exception {
        Thread caller = Thread.currentThread();
        Set<Thread> workers = ConcurrentHashMap.newKeySet();
        AtomicBoolean writerIdentityObserved = new AtomicBoolean();
        try (PaperServerAuthorityJournalWriter writer =
                     new PaperServerAuthorityJournalWriter(8, Duration.ofSeconds(5))) {
            for (int index = 0; index < 8; index++) {
                writer.execute(() -> {
                    workers.add(Thread.currentThread());
                    writerIdentityObserved.set(writer.isWriterThreadForTests());
                });
            }
            writer.awaitIdleForTests(Duration.ofSeconds(5));
        }

        assertEquals(1, workers.size());
        assertFalse(workers.contains(caller));
        assertTrue(writerIdentityObserved.get());
        assertEquals("mcace-authority-journal-writer",
                workers.iterator().next().getName());
    }

    @Test
    void queueIsBoundedAndRejectsWithoutBlockingCaller() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch queuedFinished = new CountDownLatch(1);
        try (PaperServerAuthorityJournalWriter writer =
                     new PaperServerAuthorityJournalWriter(1, Duration.ofSeconds(5))) {
            writer.execute(() -> {
                entered.countDown();
                try {
                    release.await();
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                }
            });
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            writer.execute(queuedFinished::countDown);
            assertEquals(1, writer.queuedTasksForTests());
            assertThrows(RejectedExecutionException.class,
                    () -> writer.execute(() -> { }));
            release.countDown();
            assertTrue(queuedFinished.await(5, TimeUnit.SECONDS));
            writer.awaitIdleForTests(Duration.ofSeconds(5));
        } finally {
            release.countDown();
        }
    }

    @Test
    void timedOutCloseNeverInterruptsTheWriterAndDefersResourceCloseUntilTermination()
            throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch resourceClosed = new CountDownLatch(1);
        AtomicBoolean interrupted = new AtomicBoolean();
        AtomicInteger closeCount = new AtomicInteger();
        PaperServerAuthorityJournalWriter writer =
                new PaperServerAuthorityJournalWriter(1, Duration.ofMillis(10));
        writer.execute(() -> {
            entered.countDown();
            try {
                release.await();
            } catch (InterruptedException exception) {
                interrupted.set(true);
                Thread.currentThread().interrupt();
            }
        });
        assertTrue(entered.await(5, TimeUnit.SECONDS));

        assertThrows(java.io.IOException.class, writer::close);
        assertFalse(writer.isTerminated());
        writer.closeAfterTermination(() -> {
            closeCount.incrementAndGet();
            resourceClosed.countDown();
        }, exception -> { throw new AssertionError(exception); });
        assertEquals(1L, release.getCount());
        assertFalse(interrupted.get());

        release.countDown();
        assertTrue(resourceClosed.await(5, TimeUnit.SECONDS));
        assertTrue(writer.isTerminated());
        assertFalse(interrupted.get());
        assertEquals(1, closeCount.get());
    }
}
