package com.ellan.mcace.cloud.auth;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

public final class AccessTokenCodec {
    private static final int MAGIC = 0x4d434154;
    private static final int VERSION = 1;
    private static final int MAX_PAYLOAD_BYTES = 2_048;
    private static final Duration MAX_LIFETIME = Duration.ofMinutes(10);
    private static final Duration FUTURE_SKEW = Duration.ofSeconds(30);

    private final PrivateKey signingKey;
    private final PublicKey verificationKey;
    private final Clock clock;
    private final Duration lifetime;

    public AccessTokenCodec(
            PrivateKey signingKey,
            PublicKey verificationKey,
            Clock clock,
            Duration lifetime) {
        this.signingKey = Objects.requireNonNull(signingKey, "signingKey");
        this.verificationKey = Objects.requireNonNull(verificationKey, "verificationKey");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.lifetime = Objects.requireNonNull(lifetime, "lifetime");
        if (lifetime.isZero() || lifetime.isNegative() || lifetime.compareTo(MAX_LIFETIME) > 0) {
            throw new IllegalArgumentException("invalid access token lifetime");
        }
    }

    public String issue(ServerIdentity identity) throws AuthenticationException {
        Instant issuedAt = clock.instant();
        Instant expiresAt = issuedAt.plus(lifetime);
        byte[] payload = encode(
                UUID.randomUUID(), identity.serverId(), identity.scopes(), issuedAt, expiresAt);
        byte[] signature = sign(payload);
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString(payload) + "." + encoder.encodeToString(signature);
    }

    public AuthenticatedServer verify(String token) throws AuthenticationException {
        Objects.requireNonNull(token, "token");
        if (token.length() > 4_096) throw new AuthenticationException("invalid access token");
        String[] parts = token.split("\\.", -1);
        if (parts.length != 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
            throw new AuthenticationException("invalid access token");
        }
        byte[] payload;
        byte[] signature;
        try {
            Base64.Decoder decoder = Base64.getUrlDecoder();
            payload = decoder.decode(parts[0]);
            signature = decoder.decode(parts[1]);
        } catch (IllegalArgumentException exception) {
            throw new AuthenticationException("invalid access token", exception);
        }
        if (payload.length > MAX_PAYLOAD_BYTES || signature.length != 64 || !verifySignature(payload, signature)) {
            throw new AuthenticationException("invalid access token");
        }
        return decode(payload);
    }

    private AuthenticatedServer decode(byte[] payload) throws AuthenticationException {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(payload))) {
            if (input.readInt() != MAGIC || input.readInt() != VERSION) {
                throw new AuthenticationException("invalid access token");
            }
            UUID tokenId = new UUID(input.readLong(), input.readLong());
            String serverId = readString(input, 64);
            Instant issuedAt = Instant.ofEpochMilli(input.readLong());
            Instant expiresAt = Instant.ofEpochMilli(input.readLong());
            int scopeCount = input.readUnsignedByte();
            if (scopeCount == 0 || scopeCount > ApiScope.values().length) {
                throw new AuthenticationException("invalid access token");
            }
            Set<ApiScope> scopes = EnumSet.noneOf(ApiScope.class);
            for (int index = 0; index < scopeCount; index++) {
                if (!scopes.add(ApiScope.valueOf(readString(input, 32)))) {
                    throw new AuthenticationException("invalid access token");
                }
            }
            if (input.available() != 0) throw new AuthenticationException("invalid access token");
            Instant now = clock.instant();
            if (issuedAt.isAfter(now.plus(FUTURE_SKEW)) || !expiresAt.isAfter(now)
                    || !expiresAt.isAfter(issuedAt)
                    || Duration.between(issuedAt, expiresAt).compareTo(MAX_LIFETIME) > 0) {
                throw new AuthenticationException("expired or invalid access token");
            }
            return new AuthenticatedServer(tokenId, serverId, scopes, expiresAt);
        } catch (IOException | IllegalArgumentException exception) {
            throw new AuthenticationException("invalid access token", exception);
        }
    }

    private static byte[] encode(
            UUID tokenId,
            String serverId,
            Set<ApiScope> scopes,
            Instant issuedAt,
            Instant expiresAt) throws AuthenticationException {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.writeInt(MAGIC);
                output.writeInt(VERSION);
                output.writeLong(tokenId.getMostSignificantBits());
                output.writeLong(tokenId.getLeastSignificantBits());
                writeString(output, serverId);
                output.writeLong(issuedAt.toEpochMilli());
                output.writeLong(expiresAt.toEpochMilli());
                List<ApiScope> ordered = new ArrayList<>(scopes);
                ordered.sort(java.util.Comparator.comparing(Enum::name));
                output.writeByte(ordered.size());
                for (ApiScope scope : ordered) writeString(output, scope.name());
            }
            return bytes.toByteArray();
        } catch (IOException exception) {
            throw new AuthenticationException("cannot encode access token", exception);
        }
    }

    private byte[] sign(byte[] payload) throws AuthenticationException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(signingKey);
            signature.update(payload);
            return signature.sign();
        } catch (GeneralSecurityException exception) {
            throw new AuthenticationException("cannot sign access token", exception);
        }
    }

    private boolean verifySignature(byte[] payload, byte[] signed) throws AuthenticationException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(verificationKey);
            signature.update(payload);
            return signature.verify(signed);
        } catch (GeneralSecurityException exception) {
            throw new AuthenticationException("cannot verify access token", exception);
        }
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        output.writeShort(bytes.length);
        output.write(bytes);
    }

    private static String readString(DataInputStream input, int maximumCharacters) throws IOException {
        int length = input.readUnsignedShort();
        if (length == 0 || length > maximumCharacters * 4) throw new IOException("invalid string length");
        byte[] encoded = input.readNBytes(length);
        if (encoded.length != length) throw new IOException("truncated string");
        String value = new String(encoded, StandardCharsets.UTF_8);
        if (value.length() > maximumCharacters) throw new IOException("string is too long");
        return value;
    }
}
