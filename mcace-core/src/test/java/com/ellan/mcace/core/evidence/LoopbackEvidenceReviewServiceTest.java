package com.ellan.mcace.core.evidence;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import com.ellan.mcace.protocol.generated.EvidenceType;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class LoopbackEvidenceReviewServiceTest {
    private static final byte[] PNG = Base64.getDecoder().decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGP4DwQACfsD/fteaysA"
                    + "AAAASUVORK5CYII=");

    @Test
    void servesOnlyOneCollectedGameFrameWithStrictNoStoreHeaders() throws Exception {
        MutableClock clock = new MutableClock();
        UUID evidenceId = UUID.randomUUID();
        List<EvidenceReviewAuditRecord> audits = new ArrayList<>();
        try (LoopbackEvidenceReviewService service = start(reader(evidenceId, validArtifact(evidenceId)), audits, clock)) {
            LoopbackEvidenceReviewService.ReviewLink link = service.issue(evidenceId, "operator-a", "case review");
            HttpURLConnection first = open(link.url());
            assertEquals(200, first.getResponseCode());
            assertArrayEquals(PNG, first.getInputStream().readAllBytes());
            assertEquals("no-store, max-age=0", first.getHeaderField("Cache-Control"));
            assertEquals("nosniff", first.getHeaderField("X-Content-Type-Options"));
            assertEquals("no-referrer", first.getHeaderField("Referrer-Policy"));
            assertEquals("same-origin", first.getHeaderField("Cross-Origin-Opener-Policy"));
            assertTrue(first.getHeaderField("Content-Security-Policy").startsWith("sandbox"));

            assertEquals(404, open(link.url()).getResponseCode(), "a capability is consumed before its content is read");
            assertEquals(List.of(EvidenceReviewAuditRecord.Outcome.ISSUED,
                    EvidenceReviewAuditRecord.Outcome.SERVED), audits.stream().map(EvidenceReviewAuditRecord::outcome).toList());
        }
    }

    @Test
    void expiryAndInvalidArtifactsFailWithoutLeakingDetails() throws Exception {
        MutableClock clock = new MutableClock();
        UUID evidenceId = UUID.randomUUID();
        try (LoopbackEvidenceReviewService service = start(reader(evidenceId, validArtifact(evidenceId)), new ArrayList<>(), clock)) {
            LoopbackEvidenceReviewService.ReviewLink expired = service.issue(evidenceId, "operator-a", "case review");
            clock.advance(Duration.ofSeconds(11));
            assertEquals(410, open(expired.url()).getResponseCode());
        }

        MutableClock freshClock = new MutableClock();
        UUID wrongScopeId = UUID.randomUUID();
        EvidenceReviewArtifact wrongScope = artifact(wrongScopeId, EvidenceCaptureScope.GAME_WINDOW,
                EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED, PNG, 1, 1, freshClock.instant());
        try (LoopbackEvidenceReviewService service = start(reader(wrongScopeId, wrongScope), new ArrayList<>(), freshClock)) {
            assertThrows(IllegalArgumentException.class, () -> service.issue(wrongScopeId, "operator-a", "case review"));
        }

        UUID legacyId = UUID.randomUUID();
        EvidenceReviewArtifact legacy = legacyArtifact(legacyId, freshClock.instant());
        try (LoopbackEvidenceReviewService service = start(reader(legacyId, legacy), new ArrayList<>(), freshClock)) {
            assertThrows(IllegalArgumentException.class, () -> service.issue(legacyId, "operator-a", "case review"));
        }

        UUID malformedId = UUID.randomUUID();
        EvidenceReviewArtifact malformed = artifact(malformedId, EvidenceCaptureScope.GAME_RENDER_FRAME,
                EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED, new byte[] {1, 2, 3}, 1, 1, freshClock.instant());
        try (LoopbackEvidenceReviewService service = start(reader(malformedId, malformed), new ArrayList<>(), freshClock)) {
            assertThrows(IllegalArgumentException.class, () -> service.issue(malformedId, "operator-a", "case review"));
        }

        UUID changedId = UUID.randomUUID();
        AtomicInteger reads = new AtomicInteger();
        EvidenceReviewArtifact changedMalformed = artifact(changedId, EvidenceCaptureScope.GAME_RENDER_FRAME,
                EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED, new byte[] {1, 2, 3}, 1, 1,
                freshClock.instant());
        EvidenceReviewReader changedAfterIssue = requested -> reads.getAndIncrement() == 0
                ? Optional.of(validArtifact(changedId)) : Optional.of(changedMalformed);
        try (LoopbackEvidenceReviewService service = start(changedAfterIssue, new ArrayList<>(), freshClock)) {
            assertEquals(503, open(service.issue(changedId, "operator-a", "case review").url()).getResponseCode(),
                    "the consumed capability revalidates a changed backing artifact");
        }
    }

    @Test
    void rejectsNonLoopbackBindAndOnlyOneConcurrentRequestConsumesTheGrant() throws Exception {
        MutableClock clock = new MutableClock();
        assertThrows(IllegalArgumentException.class, () -> LoopbackEvidenceReviewService.start(
                EvidenceReviewReader.disabled(), EvidenceAuditSink.noop(), clock, new SecureRandom(),
                InetAddress.getByName("0.0.0.0"), 0, Duration.ofSeconds(10), 1));

        UUID evidenceId = UUID.randomUUID();
        try (LoopbackEvidenceReviewService service = start(reader(evidenceId, validArtifact(evidenceId)), new ArrayList<>(), clock)) {
            URI url = service.issue(evidenceId, "operator-a", "case review").url();
            ExecutorService callers = Executors.newFixedThreadPool(2);
            try {
                CyclicBarrier barrier = new CyclicBarrier(2);
                Callable<Integer> get = () -> {
                    barrier.await();
                    return open(url).getResponseCode();
                };
                List<Integer> statuses = callers.invokeAll(List.of(get, get)).stream().map(result -> {
                    try {
                        return result.get();
                    } catch (Exception exception) {
                        throw new AssertionError(exception);
                    }
                }).toList();
                assertEquals(1, statuses.stream().filter(code -> code == 200).count());
                assertEquals(1, statuses.stream().filter(code -> code == 404).count());
            } finally {
                callers.shutdownNow();
            }
        }
    }

    @Test
    void reviewAuditNeverContainsCapabilityOrRawContent(@TempDir Path temporary) throws Exception {
        MutableClock clock = new MutableClock();
        UUID evidenceId = UUID.randomUUID();
        Path auditPath = temporary.resolve("review-audit.log");
        FileEvidenceAuditSink sink = new FileEvidenceAuditSink(auditPath, 4096);
        try (LoopbackEvidenceReviewService service = LoopbackEvidenceReviewService.start(
                reader(evidenceId, validArtifact(evidenceId)), sink, clock, new SecureRandom(),
                InetAddress.getLoopbackAddress(), 0, Duration.ofSeconds(10), 1)) {
            LoopbackEvidenceReviewService.ReviewLink link = service.issue(evidenceId, "operator-a", "case review");
            HttpURLConnection connection = open(link.url());
            assertEquals(200, connection.getResponseCode());
            try (var response = connection.getInputStream()) {
                response.readAllBytes();
            }
            String content = waitForAudit(auditPath, "REVIEW outcome=SERVED");
            assertTrue(content.contains("REVIEW outcome=ISSUED"));
            assertTrue(content.contains("REVIEW outcome=SERVED"));
            assertFalse(content.contains(link.url().getPath().substring(link.url().getPath().lastIndexOf('/') + 1)));
            assertFalse(content.contains(Base64.getEncoder().encodeToString(PNG)));
        }
    }

    private static String waitForAudit(Path path, String marker) throws Exception {
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(2);
        String content = "";
        while (System.nanoTime() < deadline) {
            content = Files.readString(path, StandardCharsets.UTF_8);
            if (content.contains(marker)) return content;
            Thread.sleep(10L);
        }
        return content;
    }

    @Test
    void closeClearsOutstandingCapabilities() throws Exception {
        MutableClock clock = new MutableClock();
        UUID evidenceId = UUID.randomUUID();
        LoopbackEvidenceReviewService service = start(reader(evidenceId, validArtifact(evidenceId)), new ArrayList<>(), clock);
        try {
            service.issue(evidenceId, "operator-a", "case review");
            assertEquals(1, service.status().activeTokens());
            service.close();
            assertFalse(service.status().running());
            assertEquals(0, service.status().activeTokens());
            assertThrows(IllegalStateException.class, () -> service.issue(evidenceId, "operator-a", "case review"));
        } finally {
            service.close();
        }
    }

    private static LoopbackEvidenceReviewService start(
            EvidenceReviewReader reader, EvidenceAuditSink auditSink, Clock clock) throws IOException {
        return LoopbackEvidenceReviewService.start(reader, auditSink, clock, new SecureRandom(),
                InetAddress.getLoopbackAddress(), 0, Duration.ofSeconds(10), 4);
    }

    private static LoopbackEvidenceReviewService start(
            EvidenceReviewReader reader, List<EvidenceReviewAuditRecord> audits, Clock clock) throws IOException {
        EvidenceAuditSink sink = new EvidenceAuditSink() {
            @Override public void append(EvidenceAuditRecord ignored) { }
            @Override public void appendReview(EvidenceReviewAuditRecord record) { audits.add(record); }
        };
        return start(reader, sink, clock);
    }

    private static EvidenceReviewReader reader(UUID evidenceId, EvidenceReviewArtifact artifact) {
        return requested -> requested.equals(evidenceId) ? Optional.of(artifact) : Optional.empty();
    }

    private static EvidenceReviewArtifact validArtifact(UUID evidenceId) throws Exception {
        return artifact(evidenceId, EvidenceCaptureScope.GAME_RENDER_FRAME,
                EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED, PNG, 1, 1, Instant.parse("2026-08-09T00:00:00Z"));
    }

    private static EvidenceReviewArtifact artifact(UUID evidenceId, EvidenceCaptureScope scope,
            EvidenceCollectionStatus status, byte[] content, int width, int height, Instant now) throws Exception {
        EvidenceStorageMetadata metadata = new EvidenceStorageMetadata(evidenceId, UUID.randomUUID(), "session", "request",
                "case", EvidenceType.SCREENSHOT, scope, status, now, width, height, 1,
                MessageDigest.getInstance("SHA-256").digest(content), new byte[32], 60, "policy", "review");
        return new EvidenceReviewArtifact(metadata, now.plusSeconds(60), content);
    }

    private static EvidenceReviewArtifact legacyArtifact(UUID evidenceId, Instant now) throws Exception {
        EvidenceReviewArtifact artifact = artifact(evidenceId, EvidenceCaptureScope.GAME_RENDER_FRAME,
                EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED, PNG, 1, 1, now);
        return new EvidenceReviewArtifact(artifact.metadata(), artifact.expiresAt(), artifact.content(), 1);
    }

    private static HttpURLConnection open(URI uri) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(2_000);
        connection.setReadTimeout(2_000);
        return connection;
    }

    private static final class MutableClock extends Clock {
        private Instant instant = Instant.parse("2026-08-09T00:00:00Z");
        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return instant; }
        void advance(Duration duration) { instant = instant.plus(duration); }
    }
}
