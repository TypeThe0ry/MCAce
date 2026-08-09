package com.ellan.mcace.core.persistence;

import com.ellan.mcace.core.risk.RiskEventType;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Comparator;

public final class RiskPolicyReleaseCodec {
    private static final byte[] DOMAIN = "mcace-risk-policy-release-v1".getBytes(StandardCharsets.UTF_8);

    private RiskPolicyReleaseCodec() { }

    public static byte[] hash(RiskPolicyReleaseDraft draft) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.writeInt(DOMAIN.length);
                output.write(DOMAIN);
                output.writeLong(draft.policyId().getMostSignificantBits());
                output.writeLong(draft.policyId().getLeastSignificantBits());
                write(output, draft.policy().version());
                RiskEventType[] types = RiskEventType.values().clone();
                Arrays.sort(types, Comparator.comparing(Enum::name));
                output.writeInt(types.length);
                for (RiskEventType type : types) {
                    write(output, type.name());
                    output.writeInt(draft.policy().weights().get(type));
                }
                output.writeInt(draft.policy().watchThreshold());
                output.writeInt(draft.policy().restrictedThreshold());
                output.writeInt(draft.policy().investigationThreshold());
                write(output, draft.description());
                write(output, draft.createdBy());
            }
            return MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray());
        } catch (IOException | NoSuchAlgorithmException exception) {
            throw new IllegalStateException("cannot hash risk policy release", exception);
        }
    }

    private static void write(DataOutputStream output, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(encoded.length);
        output.write(encoded);
    }
}
