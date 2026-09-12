package com.ellan.mcace.paper.behavior;

import com.ellan.mcace.protocol.ProtocolConstants;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

public record BehaviorAlert(
        UUID playerId,
        String providerEventIdSha256,
        String provider,
        String providerVersion,
        String check,
        String stableCheck,
        double violationLevel,
        boolean experimental,
        Instant observedAt) {
    public BehaviorAlert {
        Objects.requireNonNull(playerId, "playerId");
        if (providerEventIdSha256 == null
                || !providerEventIdSha256.matches("^[0-9a-f]{64}$")) {
            throw new IllegalArgumentException(
                    "providerEventIdSha256 must be exactly 32 lower-hex bytes");
        }
        provider = bounded(provider, "provider",
                ProtocolConstants.MAX_BACKEND_AUTHORITY_PROVIDER_ID_CHARS);
        providerVersion = bounded(providerVersion, "providerVersion",
                ProtocolConstants.MAX_BACKEND_AUTHORITY_PROVIDER_VERSION_CHARS);
        check = bounded(check, "check", 64);
        stableCheck = stableCheck == null || stableCheck.isBlank()
                ? check.toLowerCase(java.util.Locale.ROOT) : bounded(
                stableCheck, "stableCheck",
                ProtocolConstants.MAX_BACKEND_AUTHORITY_STABLE_CHECK_FAMILY_CHARS);
        if (!Double.isFinite(violationLevel) || violationLevel < 0.0D) {
            throw new IllegalArgumentException("violationLevel must be finite and non-negative");
        }
        Objects.requireNonNull(observedAt, "observedAt");
    }

    /**
     * Produces a domain-separated, length-framed identity for one native provider callback.
     * Adapters must use provider-native immutable fields (or an identity-cache token) rather
     * than MCAce receipt time. Re-delivery of the same callback then remains idempotent while
     * two genuinely distinct provider events retain different identities.
     */
    public static String providerEventIdSha256(String provider, String... nativeIdentityFields) {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(nativeIdentityFields, "nativeIdentityFields");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            updateFramed(digest, "mcace.behavior-provider-event.v1");
            updateFramed(digest, provider.strip().toLowerCase(java.util.Locale.ROOT));
            for (String field : nativeIdentityFields) {
                updateFramed(digest, Objects.requireNonNull(field, "nativeIdentityField"));
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static void updateFramed(MessageDigest digest, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
        digest.update(bytes);
    }

    private static String bounded(String value, String field, int maximum) {
        Objects.requireNonNull(value, field);
        String normalized = value.strip();
        if (normalized.isEmpty() || normalized.length() > maximum) {
            throw new IllegalArgumentException(field + " must contain 1-" + maximum + " characters");
        }
        return normalized;
    }
}
