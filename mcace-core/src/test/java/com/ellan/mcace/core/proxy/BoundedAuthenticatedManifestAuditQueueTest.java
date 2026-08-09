package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.session.AuthenticatedManifest;
import com.ellan.mcace.protocol.generated.AuthRequest;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class BoundedAuthenticatedManifestAuditQueueTest {
    @Test
    void saturationFailureAndCloseAreNonBlocking() throws Exception {
        CountDownLatch started = new CountDownLatch(1), release = new CountDownLatch(1), failed = new CountDownLatch(1), recovered = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        BoundedAuthenticatedManifestAuditQueue queue = new BoundedAuthenticatedManifestAuditQueue(1, 1, manifest -> {
            int call = calls.incrementAndGet();
            if (call == 1) { started.countDown(); try { release.await(); } catch (InterruptedException exception) { Thread.currentThread().interrupt(); } }
            else if (call == 2) { failed.countDown(); throw new IllegalStateException("controlled"); }
            else recovered.countDown();
        });
        try {
            assertTrue(queue.offer(manifest()));
            assertTrue(started.await(2, TimeUnit.SECONDS));
            assertTrue(queue.offer(manifest()));
            assertFalse(queue.offer(manifest()));
            assertTrue(queue.droppedCount() >= 1);
            release.countDown();
            assertTrue(failed.await(2, TimeUnit.SECONDS));
            assertTrue(queue.offer(manifest()));
            assertTrue(recovered.await(2, TimeUnit.SECONDS));
            assertTrue(queue.failureCount() >= 1);
        } finally { queue.close(); }
        assertFalse(queue.offer(manifest()));
    }

    private static AuthenticatedManifest manifest() {
        return new AuthenticatedManifest(UUID.randomUUID(), "session-123456789012", SecurityPolicy.getDefaultInstance(),
                AuthRequest.getDefaultInstance(), Instant.now());
    }
}
