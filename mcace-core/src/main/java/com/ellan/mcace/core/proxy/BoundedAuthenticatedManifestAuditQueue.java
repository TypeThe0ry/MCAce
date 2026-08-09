package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.session.AuthenticatedManifest;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/** Fast, bounded audit handoff. Saturation and handler failures never affect authentication. */
public final class BoundedAuthenticatedManifestAuditQueue implements AutoCloseable {
    private final ThreadPoolExecutor executor;
    private final Consumer<AuthenticatedManifest> handler;
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicLong failures = new AtomicLong();

    public BoundedAuthenticatedManifestAuditQueue(int workers, int capacity, Consumer<AuthenticatedManifest> handler) {
        if (workers <= 0 || workers > 4 || capacity <= 0) throw new IllegalArgumentException("invalid audit queue bounds");
        this.handler = Objects.requireNonNull(handler, "handler");
        executor = new ThreadPoolExecutor(workers, workers, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(capacity), new ThreadPoolExecutor.AbortPolicy());
    }

    /** Non-blocking; false means audit work was dropped, never that authentication failed. */
    public boolean offer(AuthenticatedManifest manifest) {
        Objects.requireNonNull(manifest, "manifest");
        try {
            executor.execute(() -> { try { handler.accept(manifest); } catch (RuntimeException ignored) { failures.incrementAndGet(); } });
            return true;
        } catch (java.util.concurrent.RejectedExecutionException ignored) {
            dropped.incrementAndGet();
            return false;
        }
    }

    public long droppedCount() { return dropped.get(); }
    public long failureCount() { return failures.get(); }
    @Override public void close() { executor.shutdownNow(); }
}
