package com.ellan.mcace.core.federation;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Fixed-one-worker, bounded, non-blocking federation audit admission queue.
 *
 * <p>{@link #offer(FederationAuditRecord)} never performs delegate I/O and never waits for queue
 * space. A full or closed queue rejects immediately. Delegate failures are counted and the same
 * worker continues with later records. Runtime state transitions that require an audit therefore
 * fail closed when the record cannot enter this queue, while rejection telemetry may be dropped
 * with an explicit saturation counter instead of blocking a proxy plugin-message thread.</p>
 */
public final class BoundedAsyncFederationAuditSink implements FederationAuditSink, AutoCloseable {
    public static final int DEFAULT_CAPACITY = 256;
    public static final Duration DEFAULT_CLOSE_TIMEOUT = Duration.ofSeconds(5);
    private static final int MAX_CAPACITY = 4096;

    private final FederationAuditSink delegate;
    private final ArrayBlockingQueue<FederationAuditRecord> queue;
    private final Object lifecycleLock = new Object();
    private final AtomicBoolean accepting = new AtomicBoolean(true);
    private final AtomicLong accepted = new AtomicLong();
    private final AtomicLong processed = new AtomicLong();
    private final AtomicLong saturated = new AtomicLong();
    private final AtomicLong handlerFailures = new AtomicLong();
    private final AtomicLong rejectedAfterClose = new AtomicLong();
    private final Thread worker;

    public BoundedAsyncFederationAuditSink(FederationAuditSink delegate, String workerName) {
        this(delegate, DEFAULT_CAPACITY, workerName);
    }

    public BoundedAsyncFederationAuditSink(
            FederationAuditSink delegate,
            int capacity,
            String workerName) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        if (capacity <= 0 || capacity > MAX_CAPACITY) {
            throw new IllegalArgumentException("invalid federation audit queue capacity");
        }
        if (workerName == null || workerName.isBlank() || workerName.length() > 128
                || workerName.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("invalid federation audit worker name");
        }
        queue = new ArrayBlockingQueue<>(capacity);
        worker = new Thread(this::runWorker, workerName);
        worker.setDaemon(true);
        worker.start();
    }

    @Override
    public void append(FederationAuditRecord record) {
        if (!offer(record)) {
            throw new IllegalStateException("federation audit queue unavailable");
        }
    }

    @Override
    public boolean offer(FederationAuditRecord record) {
        Objects.requireNonNull(record, "record");
        synchronized (lifecycleLock) {
            if (!accepting.get()) {
                rejectedAfterClose.incrementAndGet();
                return false;
            }
            if (!queue.offer(record)) {
                saturated.incrementAndGet();
                return false;
            }
            accepted.incrementAndGet();
            return true;
        }
    }

    public FederationAuditQueueStatus status() {
        return new FederationAuditQueueStatus(
                queue.remainingCapacity() + queue.size(), queue.size(), accepted.get(),
                processed.get(), saturated.get(), handlerFailures.get(), rejectedAfterClose.get(),
                !accepting.get(), worker.isAlive());
    }

    @Override
    public void close() {
        close(DEFAULT_CLOSE_TIMEOUT);
    }

    /** Stops accepting immediately and gives the daemon worker a bounded interval to drain. */
    public void close(Duration timeout) {
        Objects.requireNonNull(timeout, "timeout");
        long timeoutMillis;
        try {
            timeoutMillis = timeout.toMillis();
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException("federation audit close timeout overflow", exception);
        }
        if (timeoutMillis < 0L || timeout.compareTo(Duration.ofSeconds(30)) > 0) {
            throw new IllegalArgumentException("federation audit close timeout is outside bounds");
        }
        boolean changed;
        synchronized (lifecycleLock) {
            changed = accepting.compareAndSet(true, false);
        }
        if (changed) {
            worker.interrupt();
        }
        if (Thread.currentThread() == worker || timeoutMillis == 0L) {
            return;
        }
        try {
            worker.join(timeoutMillis);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

    private void runWorker() {
        while (accepting.get() || !queue.isEmpty()) {
            FederationAuditRecord record;
            try {
                record = queue.poll(100L, TimeUnit.MILLISECONDS);
            } catch (InterruptedException exception) {
                continue;
            }
            if (record == null) {
                continue;
            }
            try {
                delegate.append(record);
                processed.incrementAndGet();
            } catch (RuntimeException | LinkageError exception) {
                handlerFailures.incrementAndGet();
            }
        }
    }
}
