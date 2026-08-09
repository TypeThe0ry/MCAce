package com.ellan.mcace.core.persistence;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public final class AsyncSecurityAuditSink implements SecurityAuditSink, AutoCloseable {
    private final SecurityAuditSink delegate;
    private final Consumer<Exception> failureHandler;
    private final ThreadPoolExecutor executor;

    public AsyncSecurityAuditSink(
            SecurityAuditSink delegate,
            int queueCapacity,
            Consumer<Exception> failureHandler) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.failureHandler = Objects.requireNonNull(failureHandler, "failureHandler");
        if (queueCapacity < 1 || queueCapacity > 65_536) {
            throw new IllegalArgumentException("queueCapacity must be between 1 and 65536");
        }
        this.executor = new ThreadPoolExecutor(
                1,
                1,
                0,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(queueCapacity),
                Thread.ofVirtual().name("mcace-security-audit-", 0).factory(),
                new ThreadPoolExecutor.AbortPolicy());
    }

    @Override
    public void upsertSession(SessionAuditRecord session) throws SecurityPersistenceException {
        enqueue(() -> delegate.upsertSession(session));
    }

    @Override
    public void appendRiskEvent(RiskEventAuditRecord event) throws SecurityPersistenceException {
        enqueue(() -> delegate.appendRiskEvent(event));
    }

    @Override
    public StoredEvidenceMetadata appendEvidence(EvidenceMetadataDraft evidence)
            throws SecurityPersistenceException {
        return delegate.appendEvidence(evidence);
    }

    public boolean flush(Duration timeout) throws InterruptedException {
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isNegative()) throw new IllegalArgumentException("timeout must not be negative");
        java.util.concurrent.CountDownLatch marker = new java.util.concurrent.CountDownLatch(1);
        try {
            executor.execute(marker::countDown);
        } catch (RejectedExecutionException exception) {
            return executor.isTerminated();
        }
        return marker.await(timeout.toMillis(), TimeUnit.MILLISECONDS);
    }

    @Override
    public void close() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                failureHandler.accept(new SecurityPersistenceException(
                        "security audit queue did not drain within five seconds"));
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            failureHandler.accept(exception);
        }
    }

    private void enqueue(AuditOperation operation) throws SecurityPersistenceException {
        try {
            executor.execute(() -> {
                try {
                    operation.run();
                } catch (SecurityPersistenceException | RuntimeException exception) {
                    report(exception);
                }
            });
        } catch (RejectedExecutionException exception) {
            throw new SecurityPersistenceException("security audit queue is full or closed", exception);
        }
    }

    private void report(Exception exception) {
        try {
            failureHandler.accept(exception);
        } catch (RuntimeException ignored) {
            // Failure reporting must not terminate the audit worker.
        }
    }

    @FunctionalInterface
    private interface AuditOperation {
        void run() throws SecurityPersistenceException;
    }
}
