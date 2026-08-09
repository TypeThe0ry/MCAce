package com.ellan.mcace.core.persistence;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class RevocationSignatureCodecTest {
    @Test
    void verifiesCanonicalRevocationsAndRejectsChangedPayloads() throws Exception {
        KeyPair signer = Ed25519Keys.generate(new SecureRandom());
        Instant createdAt = Instant.parse("2026-08-08T10:00:01Z");
        RevocationDraft draft = new RevocationDraft(
                UUID.randomUUID(), RevocationSubjectType.CLIENT_BUILD, "bad-build",
                "OPERATOR_REVIEW_CONFIRMED", Instant.parse("2026-08-08T10:00:00Z"),
                null, "operator-a");
        byte[] hash = RevocationSignatureCodec.hash(7, draft, createdAt);
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(signer.getPrivate());
        signature.update(RevocationSignatureCodec.signingMessage(hash));
        StoredRevocation stored = new StoredRevocation(
                draft, 7, createdAt, hash, signature.sign(), "test-key");

        assertTrue(RevocationSignatureCodec.verify(stored, signer.getPublic()));

        RevocationDraft changed = new RevocationDraft(
                draft.revocationId(), draft.subjectType(), "different-build", draft.reasonCode(),
                draft.effectiveAt(), draft.expiresAt(), draft.actorId());
        StoredRevocation tampered = new StoredRevocation(
                changed, stored.sequence(), stored.createdAt(), stored.payloadSha256(),
                stored.serverSignature(), stored.signerKeyId());
        assertFalse(RevocationSignatureCodec.verify(tampered, signer.getPublic()));
    }
}
