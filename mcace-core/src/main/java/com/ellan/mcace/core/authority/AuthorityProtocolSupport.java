package com.ellan.mcace.core.authority;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.google.protobuf.Message;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.UUID;

final class AuthorityProtocolSupport {
    static final int BINDING_BYTES = 32;
    static final int CHALLENGE_BYTES = 32;
    static final int SHA256_BYTES = 32;
    private static final HexFormat HEX = HexFormat.of();

    private AuthorityProtocolSupport() {
    }

    static void rejectUnknown(Message message, String field) throws AuthorityProtocolException {
        if (!message.getUnknownFields().asMap().isEmpty()) {
            throw new AuthorityProtocolException("unknown " + field + " fields");
        }
    }

    static void requireCanonicalEncoding(byte[] encoded, Message parsed, String field)
            throws AuthorityProtocolException {
        Objects.requireNonNull(encoded, "encoded");
        Objects.requireNonNull(parsed, "parsed");
        if (!MessageDigest.isEqual(encoded, parsed.toByteArray())) {
            throw new AuthorityProtocolException(field + " is not canonically encoded");
        }
    }

    static UUID canonicalUuid(String value, String field) throws AuthorityProtocolException {
        try {
            UUID uuid = UUID.fromString(value);
            if (!uuid.toString().equals(value)) {
                throw new AuthorityProtocolException(field + " is not a canonical UUID");
            }
            return uuid;
        } catch (IllegalArgumentException exception) {
            throw new AuthorityProtocolException("invalid " + field, exception);
        }
    }

    static Instant instant(long epochMillis, String field) throws AuthorityProtocolException {
        try {
            return Instant.ofEpochMilli(epochMillis);
        } catch (DateTimeException exception) {
            throw new AuthorityProtocolException("invalid " + field, exception);
        }
    }

    static Instant add(Instant instant, Duration duration, String field) throws AuthorityProtocolException {
        try {
            return instant.plus(duration);
        } catch (DateTimeException | ArithmeticException exception) {
            throw new AuthorityProtocolException("invalid " + field, exception);
        }
    }

    static void requireExactBytes(byte[] actual, byte[] expected, String field)
            throws AuthorityProtocolException {
        Objects.requireNonNull(expected, field);
        if (!MessageDigest.isEqual(actual, expected)) {
            throw new AuthorityProtocolException(field + " mismatch");
        }
    }

    static byte[] requireLength(byte[] value, int length, String field) {
        Objects.requireNonNull(value, field);
        if (value.length != length) {
            throw new IllegalArgumentException(field + " must be " + length + " bytes");
        }
        return value.clone();
    }

    static String hex(byte[] value, String field) throws AuthorityProtocolException {
        if (value.length != SHA256_BYTES) {
            throw new AuthorityProtocolException(field + " must be SHA-256");
        }
        return HEX.formatHex(value);
    }

    static byte[] unhex(String value, String field) {
        BackendAuthorityPin.sha256(value, field);
        return HEX.parseHex(value);
    }

    static String publicKeyId(java.security.PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "publicKey");
        return sha256(publicKey.getEncoded());
    }

    static String sha256(byte[] value) { return HEX.formatHex(digest(value)); }

    static String grantCommitment(com.ellan.mcace.protocol.generated.BackendAuthorityGrant grant) {
        MessageDigest digest = sha256Digest();
        field(digest, "mcace/backend-authority/grant/v1");
        byte[] encoded = grant.toByteArray();
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(encoded.length).array());
        digest.update(encoded);
        return HEX.formatHex(digest.digest());
    }

    static long absoluteDeltaMillis(long left, long right) {
        if (left >= right) {
            long delta = left - right;
            return delta < 0L ? Long.MAX_VALUE : delta;
        }
        long delta = right - left;
        return delta < 0L ? Long.MAX_VALUE : delta;
    }

    private static byte[] digest(byte[] value) {
        return sha256Digest().digest(value);
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("JDK SHA-256 is unavailable", exception);
        }
    }

    private static void field(MessageDigest digest, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(bytes.length).array());
        digest.update(bytes);
    }

    static void requireFrameSize(byte[] encoded) throws AuthorityProtocolException {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length == 0 || encoded.length > ProtocolConstants.MAX_BACKEND_AUTHORITY_FRAME_BYTES) {
            throw new AuthorityProtocolException("backend authority frame exceeds encoded budget");
        }
    }
}
