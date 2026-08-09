package com.ellan.mcace.storage.postgres;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.persistence.EvidenceMetadataDraft;
import com.ellan.mcace.core.persistence.ObservationOrigin;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.EvidenceType;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class EvidenceChainCodecTest {
    @Test
    void hashAndSignatureBindCanonicalMetadata() throws Exception {
        KeyPair keys = Ed25519Keys.generate(new SecureRandom());
        Ed25519EvidenceChainSigner signer = new Ed25519EvidenceChainSigner(keys.getPrivate(), keys.getPublic());
        Instant storedAt = Instant.parse("2026-08-08T08:01:00Z");
        EvidenceMetadataDraft first = draft("s3://evidence/one", (byte) 1);
        EvidenceMetadataDraft second = draft("s3://evidence/two", (byte) 1);
        byte[] firstHash = EvidenceChainCodec.hash(new byte[32], 1, first, storedAt);
        byte[] secondHash = EvidenceChainCodec.hash(new byte[32], 1, second, storedAt);
        byte[] signature = signer.sign(firstHash);

        assertFalse(MessageDigest.isEqual(firstHash, secondHash));
        assertTrue(Ed25519EvidenceChainSigner.verify(firstHash, signature, keys.getPublic()));
        assertFalse(Ed25519EvidenceChainSigner.verify(secondHash, signature, keys.getPublic()));
    }

    private static EvidenceMetadataDraft draft(String uri, byte fill) {
        byte[] hash = new byte[32];
        java.util.Arrays.fill(hash, fill);
        return new EvidenceMetadataDraft(
                UUID.fromString("76cc7ef2-1f70-410f-95c4-2fe10e591349"),
                UUID.fromString("6249dc93-949e-4074-8881-95b2831f2239"),
                "session-1",
                EvidenceType.MOD_LIST,
                ObservationOrigin.CLIENT_REPORTED,
                Instant.parse("2026-08-08T08:00:00Z"),
                123,
                hash,
                uri,
                "operator-test");
    }
}
