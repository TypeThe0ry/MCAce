package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.disposition.ArtifactObservation;
import com.ellan.mcace.core.disposition.ArtifactType;
import com.ellan.mcace.core.disposition.Confidence;
import com.ellan.mcace.core.disposition.DispositionAction;
import com.ellan.mcace.core.disposition.EvaluationContext;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.DispositionPolicyDocument;
import com.ellan.mcace.protocol.generated.SignedDispositionPolicyDocument;
import com.ellan.mcace.protocol.policy.DispositionPolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class FileSignedDispositionPolicySourceTest {
    private static final long NOW = 1_786_118_400_000L;
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC);

    @TempDir Path directory;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        keyPair = Ed25519Keys.generate(new SecureRandom());
    }

    @Test
    void firstReadAtomicallyCreatesAShortLivedVerifiedObserveOnlyPolicy() throws Exception {
        Path path = directory.resolve("policy.pb");
        FileSignedDispositionPolicySource source = new FileSignedDispositionPolicySource(path, CLOCK, keyPair);

        SignedDispositionPolicyDocument signed = source.current();
        DispositionPolicyDocument document = DispositionPolicyDocuments.verify(
                signed, keyPair.getPublic(), CLOCK, Duration.ZERO);

        assertTrue(Files.isRegularFile(path));
        assertEquals("OBSERVE", document.getRolloutStage());
        assertEquals(1L, document.getSequence());
        assertEquals(0, document.getRulesCount());
        assertTrue(document.getExpiresAtEpochMs() > NOW);
        assertEquals(path, source.path());
        assertEquals(64, source.fingerprint().length());
        assertEquals(DispositionAction.OBSERVE, new SharedProxyDispositionPolicyRuntime(
                ProxyFamily.VELOCITY, source, keyPair.getPublic(), CLOCK, Duration.ZERO)
                .evaluate(context(), observation()).decision().action());
    }

    @Test
    void restartReturnsExistingBytesWithoutResigningOrChangingSequence() throws Exception {
        Path path = directory.resolve("policy.pb");
        new FileSignedDispositionPolicySource(path, CLOCK, keyPair).current();
        byte[] firstBytes = Files.readAllBytes(path);

        SignedDispositionPolicyDocument afterRestart = new FileSignedDispositionPolicySource(path, CLOCK, keyPair).current();

        assertArrayEquals(firstBytes, Files.readAllBytes(path));
        assertEquals(1L, DispositionPolicyDocument.parseFrom(afterRestart.getDocument()).getSequence());
    }

    @Test
    void malformedAndOversizeFilesAreRejectedWithoutOverwrite() throws Exception {
        Path malformed = directory.resolve("malformed.pb");
        byte[] malformedBytes = new byte[] {1, 2, 3, 4};
        Files.write(malformed, malformedBytes);
        FileSignedDispositionPolicySource malformedSource = new FileSignedDispositionPolicySource(malformed, CLOCK, keyPair);
        assertThrows(PolicyException.class, malformedSource::current);
        assertArrayEquals(malformedBytes, Files.readAllBytes(malformed));

        Path oversized = directory.resolve("oversized.pb");
        byte[] oversizedBytes = new byte[257];
        Files.write(oversized, oversizedBytes);
        FileSignedDispositionPolicySource oversizedSource =
                new FileSignedDispositionPolicySource(oversized, CLOCK, keyPair, 256);
        assertThrows(PolicyException.class, oversizedSource::current);
        assertArrayEquals(oversizedBytes, Files.readAllBytes(oversized));
    }

    @Test
    void concurrentCurrentCallsSeeOneConsistentSignedDocument() throws Exception {
        Path path = directory.resolve("policy.pb");
        List<Callable<SignedDispositionPolicyDocument>> calls = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            // Separate instances mirror independently initialized platform adapters in one JVM.
            calls.add(() -> new FileSignedDispositionPolicySource(path, CLOCK, keyPair).current());
        }
        try (ExecutorService executor = Executors.newFixedThreadPool(4)) {
            List<SignedDispositionPolicyDocument> documents = executor.invokeAll(calls).stream()
                    .map(future -> {
                        try { return future.get(); } catch (Exception exception) { throw new AssertionError(exception); }
                    }).toList();
            assertTrue(documents.stream().allMatch(documents.get(0)::equals));
        }
    }

    @Test
    void constructorDoesNotReadOrRepairAnExistingBadPolicy() throws Exception {
        Path path = directory.resolve("bad-at-startup.pb");
        Files.write(path, new byte[] {7, 7, 7});
        FileSignedDispositionPolicySource source = new FileSignedDispositionPolicySource(path, CLOCK, keyPair);
        assertTrue(Files.exists(path));
        assertFalse(Files.size(path) == 0);
        assertThrows(PolicyException.class, source::current);
    }

    private static EvaluationContext context() {
        return new EvaluationContext(UUID.randomUUID(), "proxy", "backend", "world", "mode", Set.of(), Instant.ofEpochMilli(NOW));
    }

    private static ArtifactObservation observation() {
        return new ArtifactObservation(ArtifactType.MOD, "unknown", "1", null, Map.of(),
                ObservationOrigin.CLIENT_REPORTED, Confidence.LOW, false);
    }
}
