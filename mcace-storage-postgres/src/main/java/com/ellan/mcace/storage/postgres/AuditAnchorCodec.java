package com.ellan.mcace.storage.postgres;

import com.ellan.mcace.core.persistence.SecurityPersistenceException;
import com.ellan.mcace.core.persistence.StoredAuditAnchor;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public final class AuditAnchorCodec {
    private static final byte[] DOMAIN = "mcace-audit-anchor-v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] REVOCATION_DOMAIN = "mcace-revocation-feed-v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] OPERATOR_DOMAIN = "mcace-operator-audit-v1\0".getBytes(StandardCharsets.US_ASCII);

    private AuditAnchorCodec() { }

    static MessageDigest revocationDigest() throws SecurityPersistenceException {
        return digest(REVOCATION_DOMAIN);
    }

    static MessageDigest operatorAuditDigest() throws SecurityPersistenceException {
        return digest(OPERATOR_DOMAIN);
    }

    static void updateLong(MessageDigest digest, long value) {
        digest.update(new byte[] {
                (byte) (value >>> 56), (byte) (value >>> 48), (byte) (value >>> 40), (byte) (value >>> 32),
                (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value});
    }

    static void updateBytes(MessageDigest digest, byte[] value) {
        updateLong(digest, value.length);
        digest.update(value);
    }

    static void updateText(MessageDigest digest, String value) {
        updateBytes(digest, value.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] hash(
            UUID anchorId,
            long sequence,
            Instant createdAt,
            long evidenceSequence,
            byte[] evidenceHash,
            long revocationCount,
            long revocationMaxSequence,
            byte[] revocationHash,
            long operatorAuditCount,
            byte[] operatorAuditHash,
            byte[] previousAnchorHash) throws SecurityPersistenceException {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.write(DOMAIN);
                output.writeLong(anchorId.getMostSignificantBits());
                output.writeLong(anchorId.getLeastSignificantBits());
                output.writeLong(sequence);
                output.writeLong(createdAt.getEpochSecond());
                output.writeInt(createdAt.getNano());
                output.writeLong(evidenceSequence);
                output.write(evidenceHash);
                output.writeLong(revocationCount);
                output.writeLong(revocationMaxSequence);
                output.write(revocationHash);
                output.writeLong(operatorAuditCount);
                output.write(operatorAuditHash);
                output.write(previousAnchorHash);
            }
            return MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray());
        } catch (IOException | GeneralSecurityException exception) {
            throw new SecurityPersistenceException("cannot calculate audit anchor hash", exception);
        }
    }

    public static boolean verify(StoredAuditAnchor anchor, PublicKey publicKey)
            throws SecurityPersistenceException {
        Objects.requireNonNull(anchor, "anchor");
        Objects.requireNonNull(publicKey, "publicKey");
        byte[] calculated = hash(
                anchor.anchorId(), anchor.sequence(), anchor.createdAt(), anchor.evidenceSequence(),
                anchor.evidenceChainSha256(), anchor.revocationCount(), anchor.revocationMaxSequence(),
                anchor.revocationFeedSha256(), anchor.operatorAuditCount(), anchor.operatorAuditSha256(),
                anchor.previousAnchorSha256());
        if (!MessageDigest.isEqual(calculated, anchor.anchorSha256())) {
            return false;
        }
        return Ed25519AuditAnchorSigner.verify(calculated, anchor.serverSignature(), publicKey);
    }

    private static MessageDigest digest(byte[] domain) throws SecurityPersistenceException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(domain);
            return digest;
        } catch (GeneralSecurityException exception) {
            throw new SecurityPersistenceException("SHA-256 is unavailable", exception);
        }
    }
}
