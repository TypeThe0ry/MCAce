package com.ellan.mcace.core.risk;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.UUID;

public final class PolicyCohortAssigner {
    private static final byte[] DOMAIN = "mcace-policy-cohort-v1".getBytes(StandardCharsets.UTF_8);

    private PolicyCohortAssigner() { }

    public static int bucket(UUID playerId, UUID policyId) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(policyId, "policyId");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(DOMAIN);
            digest.update(uuidBytes(playerId));
            digest.update(uuidBytes(policyId));
            long unsigned = Integer.toUnsignedLong(ByteBuffer.wrap(digest.digest()).getInt());
            return (int) (unsigned % 10_000L);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static byte[] uuidBytes(UUID value) {
        return ByteBuffer.allocate(16)
                .putLong(value.getMostSignificantBits())
                .putLong(value.getLeastSignificantBits())
                .array();
    }
}
