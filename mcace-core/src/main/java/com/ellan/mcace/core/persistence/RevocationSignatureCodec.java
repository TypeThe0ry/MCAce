package com.ellan.mcace.core.persistence;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;

public final class RevocationSignatureCodec {
    private static final int FORMAT_VERSION = 1;
    private static final byte[] SIGNATURE_DOMAIN =
            "mcace-revocation-signature-v1\0".getBytes(StandardCharsets.US_ASCII);

    private RevocationSignatureCodec() { }

    public static byte[] hash(long sequence, RevocationDraft draft, Instant createdAt)
            throws SecurityPersistenceException {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.writeInt(FORMAT_VERSION);
                output.writeLong(sequence);
                output.writeLong(draft.revocationId().getMostSignificantBits());
                output.writeLong(draft.revocationId().getLeastSignificantBits());
                writeString(output, draft.subjectType().name());
                writeString(output, draft.subjectId());
                writeString(output, draft.reasonCode());
                output.writeLong(draft.effectiveAt().toEpochMilli());
                output.writeBoolean(draft.expiresAt() != null);
                if (draft.expiresAt() != null) output.writeLong(draft.expiresAt().toEpochMilli());
                writeString(output, draft.actorId());
                output.writeLong(createdAt.toEpochMilli());
            }
            return MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray());
        } catch (IOException | GeneralSecurityException exception) {
            throw new SecurityPersistenceException("cannot encode revocation", exception);
        }
    }

    public static boolean verify(StoredRevocation stored, PublicKey trustedSigner)
            throws SecurityPersistenceException {
        try {
            byte[] calculated = hash(stored.sequence(), stored.revocation(), stored.createdAt());
            if (!MessageDigest.isEqual(calculated, stored.payloadSha256())) return false;
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(trustedSigner);
            signature.update(signingMessage(calculated));
            return signature.verify(stored.serverSignature());
        } catch (GeneralSecurityException exception) {
            throw new SecurityPersistenceException("cannot verify revocation signature", exception);
        }
    }

    public static byte[] signingMessage(byte[] payloadSha256) {
        if (payloadSha256.length != 32) throw new IllegalArgumentException("revocation hash must contain 32 bytes");
        byte[] message = new byte[SIGNATURE_DOMAIN.length + payloadSha256.length];
        System.arraycopy(SIGNATURE_DOMAIN, 0, message, 0, SIGNATURE_DOMAIN.length);
        System.arraycopy(payloadSha256, 0, message, SIGNATURE_DOMAIN.length, payloadSha256.length);
        return message;
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(encoded.length);
        output.write(encoded);
    }
}
