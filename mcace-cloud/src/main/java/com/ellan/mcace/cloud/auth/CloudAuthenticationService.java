package com.ellan.mcace.cloud.auth;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Objects;
import java.util.UUID;

public final class CloudAuthenticationService {
    private static final int MAGIC = 0x4d434143;
    private static final int VERSION = 1;
    private static final int MAX_OUTSTANDING = 10_000;
    private static final int MAX_PER_SERVER = 8;

    private final ServerIdentityRegistry identities;
    private final AccessTokenCodec tokens;
    private final Clock clock;
    private final SecureRandom random;
    private final Duration challengeLifetime;
    private final AuthenticationChallengeStore challengeStore;

    public CloudAuthenticationService(
            ServerIdentityRegistry identities,
            AccessTokenCodec tokens,
            Clock clock,
            SecureRandom random,
            Duration challengeLifetime) {
        this(identities, tokens, clock, random, challengeLifetime,
                new InMemoryAuthenticationChallengeStore());
    }

    public CloudAuthenticationService(
            ServerIdentityRegistry identities,
            AccessTokenCodec tokens,
            Clock clock,
            SecureRandom random,
            Duration challengeLifetime,
            AuthenticationChallengeStore challengeStore) {
        this.identities = Objects.requireNonNull(identities, "identities");
        this.tokens = Objects.requireNonNull(tokens, "tokens");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.random = Objects.requireNonNull(random, "random");
        this.challengeLifetime = Objects.requireNonNull(challengeLifetime, "challengeLifetime");
        this.challengeStore = Objects.requireNonNull(challengeStore, "challengeStore");
        if (challengeLifetime.isZero() || challengeLifetime.isNegative()
                || challengeLifetime.compareTo(Duration.ofMinutes(2)) > 0) {
            throw new IllegalArgumentException("invalid authentication challenge lifetime");
        }
    }

    public IssuedChallenge issue(String serverId) throws AuthenticationException {
        ServerIdentity identity = identities.find(serverId)
                .orElseThrow(() -> new AuthenticationException("server authentication failed"));
        Instant now = clock.instant();
        UUID challengeId = UUID.randomUUID();
        Instant expiresAt = now.plus(challengeLifetime);
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);
        byte[] signingPayload = encodeChallenge(challengeId, identity.serverId(), now, expiresAt, nonce);
        challengeStore.create(new StoredAuthenticationChallenge(
                challengeId, identity.serverId(), identity.publicKey().getEncoded(),
                EnumSet.copyOf(identity.scopes()), signingPayload, expiresAt),
                now, MAX_OUTSTANDING, MAX_PER_SERVER);
        return new IssuedChallenge(challengeId, signingPayload, expiresAt);
    }

    public String exchange(UUID challengeId, String serverId, String encodedSignature)
            throws AuthenticationException {
        Objects.requireNonNull(challengeId, "challengeId");
        StoredAuthenticationChallenge challenge = challengeStore.consume(challengeId)
                .orElseThrow(() -> new AuthenticationException("server authentication failed"));
        ServerIdentity.validateServerId(serverId);
        Objects.requireNonNull(encodedSignature, "encodedSignature");
        Instant now = clock.instant();
        if (!challenge.serverId().equals(serverId)
                || !challenge.expiresAt().isAfter(now)) {
            throw new AuthenticationException("server authentication failed");
        }
        byte[] signed;
        try {
            signed = Base64.getUrlDecoder().decode(encodedSignature);
        } catch (IllegalArgumentException exception) {
            throw new AuthenticationException("server authentication failed", exception);
        }
        if (signed.length != 64 || !verify(
                challenge.identity(), challenge.signingPayload(), signed)) {
            throw new AuthenticationException("server authentication failed");
        }
        return tokens.issue(challenge.identity());
    }

    public AuthenticatedServer authenticate(String token) throws AuthenticationException {
        return tokens.verify(token);
    }

    private static boolean verify(ServerIdentity identity, byte[] payload, byte[] signed)
            throws AuthenticationException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(identity.publicKey());
            signature.update(payload);
            return signature.verify(signed);
        } catch (GeneralSecurityException exception) {
            throw new AuthenticationException("server authentication failed", exception);
        }
    }

    private static byte[] encodeChallenge(
            UUID challengeId,
            String serverId,
            Instant issuedAt,
            Instant expiresAt,
            byte[] nonce) throws AuthenticationException {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.writeInt(MAGIC);
                output.writeInt(VERSION);
                output.writeLong(challengeId.getMostSignificantBits());
                output.writeLong(challengeId.getLeastSignificantBits());
                byte[] encodedServer = serverId.getBytes(StandardCharsets.US_ASCII);
                output.writeByte(encodedServer.length);
                output.write(encodedServer);
                output.writeLong(issuedAt.toEpochMilli());
                output.writeLong(expiresAt.toEpochMilli());
                output.writeByte(nonce.length);
                output.write(nonce);
            }
            return bytes.toByteArray();
        } catch (IOException exception) {
            throw new AuthenticationException("cannot encode authentication challenge", exception);
        }
    }
}
