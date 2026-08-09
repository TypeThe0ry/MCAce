package com.ellan.mcace.cloud.anchor;

import com.ellan.mcace.core.persistence.AuditAnchorPublication;
import com.ellan.mcace.core.persistence.AuditAnchorStore;
import com.ellan.mcace.core.persistence.SecurityPersistenceException;
import com.ellan.mcace.core.persistence.StoredAuditAnchor;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

public final class AuditAnchorService implements AutoCloseable {
    private static final int CLAIM_BATCH_SIZE = 16;

    private final AuditAnchorStore store;
    private final AuditAnchorPublisher publisher;
    private final Duration interval;
    private final Duration leaseDuration;
    private final Duration retryDelay;
    private final Logger logger;
    private final String workerId = "cloud-" + UUID.randomUUID();
    private final ScheduledExecutorService executor;
    private final AtomicBoolean started = new AtomicBoolean();

    public AuditAnchorService(
            AuditAnchorStore store,
            AuditAnchorPublisher publisher,
            Duration interval,
            Duration leaseDuration,
            Duration retryDelay,
            Logger logger) {
        this.store = Objects.requireNonNull(store, "store");
        this.publisher = Objects.requireNonNull(publisher, "publisher");
        this.interval = positiveBounded(interval, "interval", Duration.ofDays(1));
        this.leaseDuration = positiveBounded(leaseDuration, "leaseDuration", Duration.ofMinutes(10));
        this.retryDelay = positiveBounded(retryDelay, "retryDelay", Duration.ofHours(1));
        this.logger = Objects.requireNonNull(logger, "logger");
        this.executor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "mcace-audit-anchor-publisher");
            thread.setDaemon(true);
            return thread;
        });
    }

    public void start() {
        if (!started.compareAndSet(false, true)) {
            throw new IllegalStateException("audit anchor service is already started");
        }
        executor.scheduleWithFixedDelay(
                this::safeRunOnce, 0L, interval.toMillis(), TimeUnit.MILLISECONDS);
    }

    public void runOnce() throws SecurityPersistenceException {
        store.createAuditAnchor(interval);
        List<StoredAuditAnchor> anchors = store.claimPendingAuditAnchors(
                workerId, leaseDuration, CLAIM_BATCH_SIZE);
        for (StoredAuditAnchor anchor : anchors) {
            try {
                AuditAnchorPublication publication = publisher.publish(anchor);
                store.recordAuditAnchorPublication(anchor.anchorId(), workerId, publication);
            } catch (AuditAnchorPublicationException exception) {
                store.releaseAuditAnchorClaim(
                        anchor.anchorId(), workerId, retryDelay, safeMessage(exception));
                logger.warning("MCAce audit anchor publication failed for sequence "
                        + anchor.sequence() + ": " + safeMessage(exception));
            }
        }
    }

    @Override
    public void close() {
        executor.shutdownNow();
        try {
            executor.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        }
    }

    private void safeRunOnce() {
        try {
            runOnce();
        } catch (SecurityPersistenceException | RuntimeException exception) {
            logger.warning("MCAce audit anchor cycle failed: " + safeMessage(exception));
        }
    }

    private static Duration positiveBounded(Duration value, String field, Duration maximum) {
        Objects.requireNonNull(value, field);
        if (value.isZero() || value.isNegative() || value.compareTo(maximum) > 0) {
            throw new IllegalArgumentException(field + " is outside the supported range");
        }
        return value;
    }

    private static String safeMessage(Throwable throwable) {
        String message = throwable.getMessage();
        return message == null || message.isBlank() ? throwable.getClass().getSimpleName() : message;
    }
}
