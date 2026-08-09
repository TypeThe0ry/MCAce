package com.ellan.mcace.cloud.auth;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Objects;
import java.util.UUID;

public record StoredAuthenticationChallenge(
        UUID challengeId,
        String serverId,
        byte[] publicKeyEncoded,
        EnumSet<ApiScope> scopes,
        byte[] signingPayload,
        Instant expiresAt) {
    public StoredAuthenticationChallenge {
        Objects.requireNonNull(challengeId, "challengeId");
        ServerIdentity.validateServerId(serverId);
        publicKeyEncoded = copyBounded(publicKeyEncoded, "publicKeyEncoded", 32, 128);
        scopes = EnumSet.copyOf(Objects.requireNonNull(scopes, "scopes"));
        if (scopes.isEmpty()) {
            throw new IllegalArgumentException("authentication challenge requires at least one scope");
        }
        signingPayload = copyBounded(signingPayload, "signingPayload", 64, 1024);
        Objects.requireNonNull(expiresAt, "expiresAt");
    }

    @Override public byte[] publicKeyEncoded() { return publicKeyEncoded.clone(); }
    @Override public EnumSet<ApiScope> scopes() { return EnumSet.copyOf(scopes); }
    @Override public byte[] signingPayload() { return signingPayload.clone(); }

    ServerIdentity identity() throws AuthenticationException {
        try {
            return new ServerIdentity(serverId, Ed25519Keys.decodePublic(publicKeyEncoded), scopes);
        } catch (EnvelopeException exception) {
            throw new AuthenticationException("server authentication failed", exception);
        }
    }

    private static byte[] copyBounded(byte[] value, String field, int minimum, int maximum) {
        Objects.requireNonNull(value, field);
        if (value.length < minimum || value.length > maximum) {
            throw new IllegalArgumentException(field + " has an invalid length");
        }
        return Arrays.copyOf(value, value.length);
    }
}
