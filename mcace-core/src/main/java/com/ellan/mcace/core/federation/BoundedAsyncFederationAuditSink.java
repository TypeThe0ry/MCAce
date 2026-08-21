package com.ellan.mcace.core.federation;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Fixed-one-worker, bounded federation audit sink with explicit admission and commit semantics.
 *
 * <p>{@link #offer(FederationAuditRecord)} is non-blocking and reports queue admission only. It is
 * suitable for telemetry about an operation that is already inert. {@link #append(FederationAuditRecord)}
 * waits for a bounded worker acknowledgement and returns only after the delegate has completed its
 * durable append. A delegate failure or commit timeout permanently faults this sink, rejects future
 * work, and releases every waiting caller with failure. Federation runtimes use only the durable
 * path before a successful state transition.</p>
 */
public final class BoundedAsyncFederationAuditSink implements FederationAuditSink, AutoCloseable {
    public static final int DEFAULT_CAPACITY = 256;
    public static final Duration DEFAULT_CLOSE_TIMEOUT = Duration.ofSeconds(5);
    public static final Duration DEFAULT_COMMIT_TIMEOUT = Duration.ofSeconds(5);
    private static final int MAX_CAPACITY = 4096;
    private static final Duration MAX_TIMEOUT = Duration.ofSeconds(30);

    private final FederationAuditSink delegate;
    private final ArrayBlockingQueue<AuditWork> queue;
    private final int capacity;
    private final Duration commitTimeout;
    private final Object lifecycleLock = new Object();
    private final AtomicBoolean accepting = new AtomicBoolean(true);
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean faulted = new AtomicBoolean();
    private final AtomicLong accepted = new AtomicLong();
    private final AtomicLong processed = new AtomicLong();
    private final AtomicLong saturated = new AtomicLong();
    private final AtomicLong handlerFailures = new AtomicLong();
    private final AtomicLong rejectedAfterClose = new AtomicLong();
    private final AtomicLong rejectedAfterFault = new AtomicLong();
    private final AtomicLong commitTimeouts = new AtomicLong();
    private final AtomicLong discardedAfterFault = new AtomicLong();
    private final Thread worker;

    public BoundedAsyncFederationAuditSink(FederationAuditSink delegate, String workerName) {
        this(delegate, DEFAULT_CAPACITY, workerName, DEFAULT_COMMIT_TIMEOUT);
    }

    public BoundedAsyncFederationAuditSink(
            FederationAuditSink delegate,
            int capacity,
            String workerName) {
        this(delegate, capacity, workerName, DEFAULT_COMMIT_TIMEOUT);
    }

    public BoundedAsyncFederationAuditSink(
            FederationAuditSink delegate,
            int capacity,
            String workerName,
            Duration commitTimeout) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        if (capacity <= 0 || capacity > MAX_CAPACITY) {
            throw new IllegalArgumentException("invalid federation audit queue capacity");
        }
        if (workerName == null || workerName.isBlank() || workerName.length() > 128
                || workerName.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("invalid federation audit worker name");
        }
        this.commitTimeout = requireTimeout(commitTimeout, "commit");
        this.capacity = capacity;
        queue = new ArrayBlockingQueue<>(capacity);
        worker = new Thread(this::runWorker, workerName);
        worker.setDaemon(true);
        worker.start();
    }

    /** Enqueues and waits for the worker to confirm the delegate append, never merely admission. */
    @Override
    public void append(FederationAuditRecord record) {
        Objects.requireNonNull(record, "record");
        CompletableFuture<Void> completion = new CompletableFuture<>();
        if (!enqueue(new AuditWork(record, completion))) {
            tripFault();
            throw new IllegalStateException("federation audit durable append unavailable");
        }
        try {
            completion.get(commitTimeout.toNanos(), TimeUnit.NANOSECONDS);
        } catch (TimeoutException exception) {
            commitTimeouts.incrementAndGet();
            completion.completeExceptionally(exception);
            tripFault();
            throw new IllegalStateException("federation audit durable append timed out", exception);
        } catch (ExecutionException exception) {
            throw new IllegalStateException("federation audit durable append failed", exception.getCause());
        } catch (InterruptedException exception) {
            completion.completeExceptionally(exception);
            tripFault();
            Thread.currentThread().interrupt();
            throw new IllegalStateException("federation audit durable append interrupted", exception);
        }
    }

    /** Non-blocking admission only; true never means that the delegate has committed the record. */
    @Override
    public boolean offer(FederationAuditRecord record) {
        boolean admitted = enqueue(new AuditWork(Objects.requireNonNull(record, "record"), null));
        if (!admitted && !closed.get()) {
            tripFault();
        }
        return admitted;
    }

    @Override
    public FederationAuditHealth health() {
        FederationAuditQueueStatus current = status();
        long failures = current.handlerFailures() + current.commitTimeouts()
                + current.saturated() + current.rejectedAfterClose() + current.rejectedAfterFault();
        return new FederationAuditHealth(
                current.healthy(), current.queued(), current.processed(), failures);
    }

    public FederationAuditQueueStatus status() {
        return new FederationAuditQueueStatus(
                capacity, queue.size(), accepted.get(), processed.get(), saturated.get(),
                handlerFailures.get(), rejectedAfterClose.get(), rejectedAfterFault.get(),
                commitTimeouts.get(), discardedAfterFault.get(), closed.get(), faulted.get(),
                worker.isAlive());
    }

    @Override
    public void close() {
        close(DEFAULT_CLOSE_TIMEOUT);
    }

    /** Stops accepting immediately and gives the daemon worker a bounded interval to drain. */
    public void close(Duration timeout) {
        Duration boundedTimeout = requireTimeoutAllowZero(timeout, "close");
        synchronized (lifecycleLock) {
            closed.set(true);
            accepting.set(false);
        }
        if (Thread.currentThread() == worker || boundedTimeout.isZero()) {
            return;
        }
        try {
            worker.join(boundedTimeout.toMillis());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

    private boolean enqueue(AuditWork work) {
        synchronized (lifecycleLock) {
            if (closed.get()) {
                rejectedAfterClose.incrementAndGet();
                return false;
            }
            if (faulted.get() || !accepting.get() || !worker.isAlive()) {
                rejectedAfterFault.incrementAndGet();
                return false;
            }
            if (!queue.offer(work)) {
                saturated.incrementAndGet();
                return false;
            }
            accepted.incrementAndGet();
            return true;
        }
    }

    private void runWorker() {
        while (accepting.get() || !queue.isEmpty()) {
            AuditWork work;
            try {
                work = queue.poll(100L, TimeUnit.MILLISECONDS);
            } catch (InterruptedException exception) {
                continue;
            }
            if (work == null) {
                continue;
            }
            try {
                delegate.append(work.record());
                processed.incrementAndGet();
                work.complete();
            } catch (RuntimeException | LinkageError exception) {
                handlerFailures.incrementAndGet();
                work.fail();
                tripFault();
            }
        }
    }

    private void tripFault() {
        List<AuditWork> discarded = new ArrayList<>();
        boolean changed;
        synchronized (lifecycleLock) {
            changed = faulted.compareAndSet(false, true);
            accepting.set(false);
            if (changed) {
                queue.drainTo(discarded);
                discardedAfterFault.addAndGet(discarded.size());
            }
        }
        for (AuditWork work : discarded) {
            work.fail();
        }
        if (changed && Thread.currentThread() != worker) {
            worker.interrupt();
        }
    }

    private static Duration requireTimeout(Duration timeout, String name) {
        Duration result = requireTimeoutAllowZero(timeout, name);
        if (result.isZero()) {
            throw new IllegalArgumentException("federation audit " + name + " timeout must be positive");
        }
        return result;
    }

    private static Duration requireTimeoutAllowZero(Duration timeout, String name) {
        Objects.requireNonNull(timeout, "timeout");
        try {
            timeout.toNanos();
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException("federation audit " + name + " timeout overflow", exception);
        }
        if (timeout.isNegative() || timeout.compareTo(MAX_TIMEOUT) > 0) {
            throw new IllegalArgumentException("federation audit " + name + " timeout is outside bounds");
        }
        return timeout;
    }

    private record AuditWork(
            FederationAuditRecord record,
            CompletableFuture<Void> completion) {
        private AuditWork {
            Objects.requireNonNull(record, "record");
        }

        private void complete() {
            if (completion != null) {
                completion.complete(null);
            }
        }

        private void fail() {
            if (completion != null) {
                completion.completeExceptionally(
                        new IllegalStateException("federation audit worker failed closed"));
            }
        }
    }
}
