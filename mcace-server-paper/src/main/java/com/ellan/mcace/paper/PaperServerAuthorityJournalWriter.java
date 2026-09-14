package com.ellan.mcace.paper;

import java.io.Closeable;
import java.io.IOException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * One bounded, dedicated authority journal writer.
 *
 * <p>Paper/Folia player schedulers may enqueue immutable issuance work here, but they never run
 * journal {@code force(true)} themselves. One worker preserves the journal's strict sequence and
 * lifetime-lock ordering. Queue saturation rejects immediately instead of blocking a player
 * scheduler or allocating an unbounded backlog.</p>
 */
final class PaperServerAuthorityJournalWriter implements Closeable {
    static final int DEFAULT_QUEUE_CAPACITY = 256;
    private static final Duration DEFAULT_SHUTDOWN_TIMEOUT = Duration.ofSeconds(30);

    private final ThreadPoolExecutor executor;
    private final AtomicReference<Thread> writerThread = new AtomicReference<>();
    private final Duration shutdownTimeout;
    private boolean closed;

    PaperServerAuthorityJournalWriter() {
        this(DEFAULT_QUEUE_CAPACITY, DEFAULT_SHUTDOWN_TIMEOUT);
    }

    PaperServerAuthorityJournalWriter(int queueCapacity, Duration shutdownTimeout) {
        if (queueCapacity <= 0) {
            throw new IllegalArgumentException("queueCapacity must be positive");
        }
        this.shutdownTimeout = requirePositive(shutdownTimeout);
        ThreadFactory threadFactory = task -> {
            Thread thread = new Thread(task, "mcace-authority-journal-writer");
            thread.setDaemon(true);
            writerThread.set(thread);
            return thread;
        };
        this.executor = new ThreadPoolExecutor(
                1, 1, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(queueCapacity), threadFactory,
                new ThreadPoolExecutor.AbortPolicy());
    }

    void execute(Runnable task) {
        Objects.requireNonNull(task, "task");
        synchronized (this) {
            if (closed) {
                throw new RejectedExecutionException("authority journal writer is closed");
            }
            executor.execute(task);
        }
    }

    void awaitIdleForTests(Duration timeout)
            throws InterruptedException, ExecutionException, TimeoutException {
        if (Thread.currentThread() == writerThread.get()) {
            throw new IllegalStateException("authority writer cannot await itself");
        }
        Future<?> barrier;
        synchronized (this) {
            if (closed) {
                if (executor.isTerminated()) return;
                throw new RejectedExecutionException("authority journal writer is closing");
            }
            barrier = executor.submit(() -> { });
        }
        barrier.get(requirePositive(timeout).toMillis(), TimeUnit.MILLISECONDS);
    }

    boolean isWriterThreadForTests() {
        return Thread.currentThread() == writerThread.get();
    }

    int queuedTasksForTests() {
        return executor.getQueue().size();
    }

    @Override
    public void close() throws IOException {
        synchronized (this) {
            if (!closed) {
                closed = true;
                executor.shutdown();
            }
        }
        boolean interrupted = false;
        try {
            if (!executor.awaitTermination(shutdownTimeout.toMillis(), TimeUnit.MILLISECONDS)) {
                // Do not interrupt an in-flight append/force or abandon queued issuance work.
                // The owning runtime must keep the journal handle alive until this executor has
                // actually terminated, then close it through closeAfterTermination below.
                throw new IOException("authority journal writer is still draining");
            }
        } catch (InterruptedException exception) {
            interrupted = true;
            throw new IOException("interrupted while closing authority journal writer", exception);
        } finally {
            if (interrupted) Thread.currentThread().interrupt();
        }
    }

    boolean isTerminated() {
        return executor.isTerminated();
    }

    /**
     * Closes an issuer/journal resource only after the last writer task has exited.
     *
     * <p>This is used only when the bounded graceful close timed out or was interrupted.  It
     * prevents the plugin shutdown thread from racing a still-running append against a closed
     * journal handle.</p>
     */
    void closeAfterTermination(AutoCloseable resource, Consumer<Exception> failureHandler) {
        Objects.requireNonNull(resource, "resource");
        Objects.requireNonNull(failureHandler, "failureHandler");
        synchronized (this) {
            if (!closed) {
                throw new IllegalStateException("authority writer must be closing first");
            }
        }
        if (executor.isTerminated()) {
            closeDeferredResource(resource, failureHandler);
            return;
        }
        Thread reaper = new Thread(() -> {
            boolean interrupted = false;
            try {
                while (!executor.isTerminated()) {
                    try {
                        executor.awaitTermination(1L, TimeUnit.DAYS);
                    } catch (InterruptedException exception) {
                        interrupted = true;
                    }
                }
                closeDeferredResource(resource, failureHandler);
            } finally {
                if (interrupted) Thread.currentThread().interrupt();
            }
        }, "mcace-authority-journal-reaper");
        reaper.setDaemon(true);
        reaper.start();
    }

    private static void closeDeferredResource(
            AutoCloseable resource, Consumer<Exception> failureHandler) {
        try {
            resource.close();
        } catch (Exception exception) {
            failureHandler.accept(exception);
        }
    }

    private static Duration requirePositive(Duration value) {
        Objects.requireNonNull(value, "value");
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException("duration must be positive");
        }
        return value;
    }
}
