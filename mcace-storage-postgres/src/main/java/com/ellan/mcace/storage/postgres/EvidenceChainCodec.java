package com.ellan.mcace.storage.postgres;

import com.ellan.mcace.core.persistence.EvidenceMetadataDraft;
import com.ellan.mcace.core.persistence.SecurityPersistenceException;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Objects;

final class EvidenceChainCodec {
    private static final byte[] DOMAIN = "mcace-evidence-chain-v1\0".getBytes(StandardCharsets.US_ASCII);

    private EvidenceChainCodec() {
    }

    static byte[] hash(
            byte[] previous,
            long sequence,
            EvidenceMetadataDraft evidence,
            Instant storedAt) throws SecurityPersistenceException {
        Objects.requireNonNull(previous, "previous");
        Objects.requireNonNull(evidence, "evidence");
        Objects.requireNonNull(storedAt, "storedAt");
        if (previous.length != 32 || sequence <= 0) {
            throw new SecurityPersistenceException("invalid evidence chain predecessor");
        }
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(buffer)) {
                output.write(DOMAIN);
                output.write(previous);
                output.writeLong(sequence);
                output.writeLong(evidence.evidenceId().getMostSignificantBits());
                output.writeLong(evidence.evidenceId().getLeastSignificantBits());
                output.writeLong(evidence.playerId().getMostSignificantBits());
                output.writeLong(evidence.playerId().getLeastSignificantBits());
                writeString(output, evidence.sessionId());
                writeString(output, evidence.type().name());
                writeString(output, evidence.origin().name());
                output.writeLong(evidence.capturedAt().toEpochMilli());
                output.writeLong(storedAt.toEpochMilli());
                output.writeLong(evidence.contentSize());
                output.write(evidence.contentSha256());
                writeString(output, evidence.storageUri());
                writeString(output, evidence.operatorId());
            }
            return MessageDigest.getInstance("SHA-256").digest(buffer.toByteArray());
        } catch (IOException | NoSuchAlgorithmException exception) {
            throw new SecurityPersistenceException("cannot calculate evidence chain hash", exception);
        }
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(encoded.length);
        output.write(encoded);
    }
}
