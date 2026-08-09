package com.ellan.mcace.core.evidence;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceCollectionStatus;
import com.ellan.mcace.protocol.generated.EvidenceType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class EncryptedEvidenceContentStoreTest {
    private static final Instant NOW = Instant.parse("2026-08-09T00:00:00Z");

    @Test
    void roundTripUsesIndependentAesKeyAndBoundedOpaqueUri(@TempDir Path temp) throws Exception {
        EncryptedEvidenceContentStore store = store(temp, 2, 4096);
        EvidenceContentStore.EvidenceContent content = content("hello".getBytes());
        EvidenceStorageMetadata metadata = metadata(content, "case-a");
        assertTrue(store.store(content, metadata).storageUri().startsWith("evidence://encrypted/"));
        assertArrayEquals(content.content(), store.read(content.evidenceId(), metadata));
        EvidenceReviewArtifact review = store.readForReview(content.evidenceId()).orElseThrow();
        assertEquals(metadata.evidenceId(), review.metadata().evidenceId());
        assertArrayEquals(content.content(), review.content());
        assertTrue(Files.readAllBytes(temp.resolve(content.evidenceId() + ".mce"))[4] == 2);
        assertTrue(store.status().enabled());
    }

    @Test
    void v2ReviewSurvivesRestartAndWrongKeyOrTamperFailsClosed(@TempDir Path temp) throws Exception {
        EncryptedEvidenceContentStore store = store(temp, 2, 4096);
        EvidenceContentStore.EvidenceContent content = content("hello".getBytes());
        EvidenceStorageMetadata metadata = metadata(content, "case-a");
        store.store(content, metadata);
        assertArrayEquals(content.content(), store(temp, 2, 4096).readForReview(content.evidenceId()).orElseThrow().content());
        EncryptedEvidenceContentStore wrong = new EncryptedEvidenceContentStore(temp,
                new SecretKeySpec(new byte[] {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "AES"), new SecureRandom(),
                Clock.fixed(NOW, ZoneOffset.UTC), disclosure(), 1024, 2, 4096);
        assertThrows(Exception.class, () -> wrong.readForReview(content.evidenceId()));
        Path path = temp.resolve(content.evidenceId() + ".mce"); byte[] bytes = Files.readAllBytes(path); bytes[bytes.length - 1] ^= 1; Files.write(path, bytes);
        assertThrows(Exception.class, () -> store.readForReview(content.evidenceId()));
    }

    @Test
    void v1FixtureRemainsReadableOnlyWithCallerSuppliedMetadata(@TempDir Path temp) throws Exception {
        EncryptedEvidenceContentStore store = store(temp, 2, 4096);
        EvidenceContentStore.EvidenceContent content = content("legacy".getBytes());
        EvidenceStorageMetadata metadata = metadata(content, "case-a");
        writeV1(temp.resolve(content.evidenceId() + ".mce"), content, metadata);
        assertArrayEquals(content.content(), store.read(content.evidenceId(), metadata));
        assertTrue(store.readForReview(content.evidenceId()).isEmpty());
    }

    @Test
    void authenticationCoversHeaderCiphertextAndAad(@TempDir Path temp) throws Exception {
        EncryptedEvidenceContentStore store = store(temp, 2, 4096);
        EvidenceContentStore.EvidenceContent content = content("hello".getBytes());
        EvidenceStorageMetadata metadata = metadata(content, "case-a");
        store.store(content, metadata);
        Path path = temp.resolve(content.evidenceId() + ".mce");
        byte[] original = Files.readAllBytes(path);
        byte[] bytes = original.clone();
        bytes[5] ^= 1; // authenticated expiration header nonce
        Files.write(path, bytes);
        assertThrows(Exception.class, () -> store.read(content.evidenceId(), metadata));
        Files.write(path, original);
        store.delete(content.evidenceId());

        store.store(content, metadata);
        bytes = Files.readAllBytes(path);
        bytes[bytes.length - 1] ^= 1; // GCM ciphertext/tag
        Files.write(path, bytes);
        assertThrows(Exception.class, () -> store.read(content.evidenceId(), metadata));
        assertThrows(Exception.class, () -> store.read(content.evidenceId(), metadata(content, "case-b")));
    }

    @Test
    void quotaAndTamperedExpirationSweepFailClosed(@TempDir Path temp) throws Exception {
        EncryptedEvidenceContentStore store = store(temp, 1, 2048);
        EvidenceContentStore.EvidenceContent content = content("hello".getBytes());
        EvidenceStorageMetadata metadata = metadata(content, "case-a");
        store.store(content, metadata);
        EvidenceContentStore.EvidenceContent second = content("world".getBytes());
        assertThrows(Exception.class, () -> store.store(second, metadata(second, "case-b")));

        Path path = temp.resolve(content.evidenceId() + ".mce");
        byte[] bytes = Files.readAllBytes(path);
        bytes[5 + 12] ^= 1; // authenticated expiration ciphertext/tag
        Files.write(path, bytes);
        assertThrows(Exception.class, () -> store.sweepExpired(1));
        assertTrue(Files.exists(path));
    }

    @Test
    void malformedKeyAndRetentionPolicyAreRejected(@TempDir Path temp) {
        assertThrows(IllegalArgumentException.class, () -> new EncryptedEvidenceContentStore(
                temp, new SecretKeySpec(new byte[16], "AES"), new SecureRandom(),
                Clock.fixed(NOW, ZoneOffset.UTC), disclosure(), 1024, 1, 2048));
        assertThrows(IllegalArgumentException.class, () -> new EvidenceContentStore.RetentionDisclosure(
                true, 86_401, "policy", "purpose"));
    }

    private static EncryptedEvidenceContentStore store(Path root, int maxFiles, long maxTotal) throws Exception {
        return new EncryptedEvidenceContentStore(root, new SecretKeySpec(new byte[32], "AES"),
                new SecureRandom(), Clock.fixed(NOW, ZoneOffset.UTC), disclosure(), 1024, maxFiles, maxTotal);
    }

    private static EvidenceContentStore.RetentionDisclosure disclosure() {
        return new EvidenceContentStore.RetentionDisclosure(true, 60, "policy", "purpose");
    }

    private static EvidenceContentStore.EvidenceContent content(byte[] bytes) {
        return new EvidenceContentStore.EvidenceContent(UUID.randomUUID(), UUID.randomUUID(), "session",
                "request", NOW, bytes, sha256(bytes));
    }

    private static EvidenceStorageMetadata metadata(EvidenceContentStore.EvidenceContent content, String caseId) {
        return new EvidenceStorageMetadata(content.evidenceId(), content.playerId(), content.sessionId(),
                content.requestId(), caseId, EvidenceType.SCREENSHOT, EvidenceCaptureScope.GAME_RENDER_FRAME,
                EvidenceCollectionStatus.EVIDENCE_COLLECTION_COLLECTED, content.capturedAt(), 1, 1, 1,
                content.contentSha256(), content.contentSha256(), 60, "policy", "purpose");
    }

    private static byte[] sha256(byte[] bytes) {
        try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
        catch (Exception exception) { throw new AssertionError(exception); }
    }

    private static void writeV1(Path path, EvidenceContentStore.EvidenceContent content,
            EvidenceStorageMetadata metadata) throws Exception {
        byte[] key = new byte[32], headerNonce = new byte[12], payloadNonce = new byte[12];
        payloadNonce[0] = 1; // A GCM key must never reuse a nonce, including in a legacy fixture.
        byte[] expiry = ByteBuffer.allocate(8).putLong(NOW.plusSeconds(60).toEpochMilli()).array();
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, headerNonce));
        cipher.updateAAD(content.evidenceId().toString().getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        byte[] header = cipher.doFinal(expiry);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, payloadNonce));
        cipher.updateAAD(metadata.aad()); byte[] body = cipher.doFinal(content.content());
        java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
        try (java.io.DataOutputStream out = new java.io.DataOutputStream(bytes)) {
            out.writeInt(0x4D434553); out.writeByte(1); out.write(headerNonce); out.write(header); out.write(payloadNonce); out.write(body);
        }
        Files.write(path, bytes.toByteArray());
    }
}
