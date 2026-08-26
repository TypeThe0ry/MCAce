package com.ellan.mcace.client.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.client.session.ClientHandshakeEngine;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.LoaderType;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

final class ConnectionEnablementAuthorizationTest {
    private static final byte[] REQUEST_A = new byte[32];
    private static final byte[] REQUEST_B = filled((byte) 1);
    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-08-26T00:00:00Z"), ZoneOffset.UTC);
    private static final UUID PLAYER =
            UUID.fromString("11111111-2222-3333-4444-555555555555");

    @Test
    void humanApprovalAllowsOneAssertionAndOnlyExactRetryAfterLocalFailure() throws Exception {
        ConnectionEnablementAuthorization authorization =
                ConnectionEnablementAuthorization.humanVisible(engine(), 7L);

        assertTrue(authorization.tryBeginSourceExport("assertion-a", REQUEST_A));
        assertFalse(authorization.tryBeginSourceExport("assertion-a", REQUEST_A));
        assertFalse(authorization.tryBeginSourceExport("assertion-b", REQUEST_A));
        assertFalse(authorization.releaseSourceExportAfterLocalFailure("assertion-b", REQUEST_A));
        assertTrue(authorization.releaseSourceExportAfterLocalFailure("assertion-a", REQUEST_A));
        assertFalse(authorization.tryBeginSourceExport("assertion-b", REQUEST_A));
        assertFalse(authorization.tryBeginSourceExport("assertion-a", REQUEST_B));
        assertTrue(authorization.tryBeginSourceExport("assertion-a", REQUEST_A));
        assertTrue(authorization.commitSourceExport("assertion-a", REQUEST_A));
        assertFalse(authorization.tryBeginSourceExport("assertion-a", REQUEST_A));
        assertFalse(authorization.releaseSourceExportAfterLocalFailure("assertion-a", REQUEST_A));
    }

    @Test
    void concurrentDistinctExportsHaveExactlyOneWinner() throws Exception {
        ConnectionEnablementAuthorization authorization =
                ConnectionEnablementAuthorization.humanVisible(engine(), 7L);
        AtomicInteger winners = new AtomicInteger();
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            for (String assertion : Set.of("assertion-a", "assertion-b")) {
                executor.submit(() -> {
                    ready.countDown();
                    start.await();
                    if (authorization.tryBeginSourceExport(assertion, REQUEST_A)) {
                        winners.incrementAndGet();
                    }
                    return null;
                });
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            executor.shutdown();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }
        assertEquals(1, winners.get());
    }

    @Test
    void concurrentExactRetriesHaveExactlyOneInFlightWinner() throws Exception {
        ConnectionEnablementAuthorization authorization =
                ConnectionEnablementAuthorization.humanVisible(engine(), 7L);
        AtomicInteger winners = new AtomicInteger();
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            for (int index = 0; index < 2; index++) {
                executor.submit(() -> {
                    ready.countDown();
                    start.await();
                    if (authorization.tryBeginSourceExport("assertion-a", REQUEST_A)) {
                        winners.incrementAndGet();
                    }
                    return null;
                });
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            executor.shutdown();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }
        assertEquals(1, winners.get());
    }

    @Test
    void oneConnectionAllowsAtMostOneCapturedFrameAndOnlyExactZeroContentRelease() throws Exception {
        ConnectionEnablementAuthorization authorization =
                ConnectionEnablementAuthorization.humanVisible(engine(), 7L);

        assertFalse(authorization.tryBeginEvidenceCapture(" request-a", "evidence-a"));
        assertTrue(authorization.tryBeginEvidenceCapture("request-a", "evidence-a"));
        assertFalse(authorization.tryBeginEvidenceCapture("request-a", "evidence-a"));
        assertFalse(authorization.tryBeginEvidenceCapture("request-b", "evidence-b"));
        assertFalse(authorization.releaseEvidenceCaptureWithoutContent("request-b", "evidence-b"));
        assertFalse(authorization.commitEvidenceCapture("request-b", "evidence-b"));
        assertTrue(authorization.releaseEvidenceCaptureWithoutContent("request-a", "evidence-a"));

        assertTrue(authorization.tryBeginEvidenceCapture("request-b", "evidence-b"));
        assertTrue(authorization.commitEvidenceCapture("request-b", "evidence-b"));
        assertFalse(authorization.tryBeginEvidenceCapture("request-c", "evidence-c"));
        assertFalse(authorization.releaseEvidenceCaptureWithoutContent("request-b", "evidence-b"));
    }

    @Test
    void concurrentEvidenceReservationsHaveExactlyOneWinner() throws Exception {
        ConnectionEnablementAuthorization authorization =
                ConnectionEnablementAuthorization.humanVisible(engine(), 7L);
        AtomicInteger winners = new AtomicInteger();
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            for (String request : Set.of("request-a", "request-b")) {
                executor.submit(() -> {
                    ready.countDown();
                    start.await();
                    if (authorization.tryBeginEvidenceCapture(request, "evidence-" + request)) {
                        winners.incrementAndGet();
                    }
                    return null;
                });
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            executor.shutdown();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }
        assertEquals(1, winners.get());
    }

    @Test
    void inheritedApprovalCannotExportAndCannotPromoteWithoutVaultReceipt() throws Exception {
        ClientHandshakeEngine candidate = engine();
        FederationTokenVault.TargetHandshakeClaim claim = new FederationTokenVault.TargetHandshakeClaim(
                candidate, Set.of("options.txt"), "assertion-a", "target",
                CLOCK.millis() + 60_000L, 60_000L);
        ConnectionEnablementAuthorization authorization =
                ConnectionEnablementAuthorization.federationInherited(candidate, 7L, claim);

        assertTrue(authorization.isInheritedProvisional());
        assertFalse(authorization.tryBeginSourceExport("assertion-b", REQUEST_A));
        assertFalse(authorization.tryBeginEvidenceCapture("request-a", "evidence-a"));
        assertFalse(authorization.promoteAfterPresentationCommit(null));
        assertTrue(authorization.isInheritedProvisional());
        assertFalse(authorization.tryBeginSourceExport("assertion-c", REQUEST_A));
    }

    @Test
    void cancellationOwnershipIsCandidateAndGenerationScoped() throws Exception {
        ClientHandshakeEngine current = engine();
        ClientHandshakeEngine replacement = engine();
        ConnectionEnablementAuthorization authorization =
                ConnectionEnablementAuthorization.humanVisible(current, 7L);

        assertTrue(authorization.owns(current, 7L));
        assertFalse(authorization.owns(current, 8L));
        assertFalse(authorization.owns(replacement, 7L));

        authorization.invalidate();
        assertFalse(authorization.owns(current, 7L));
    }

    private static ClientHandshakeEngine engine() throws Exception {
        return new ClientHandshakeEngine(
                PLAYER, "client", "1.21.11", "build", LoaderType.FABRIC,
                Ed25519Keys.generate(new SecureRandom()).getPublic(), CLOCK, new SecureRandom());
    }

    private static byte[] filled(byte value) {
        byte[] bytes = new byte[32];
        java.util.Arrays.fill(bytes, value);
        return bytes;
    }
}
