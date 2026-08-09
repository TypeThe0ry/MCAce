package com.ellan.mcace.client.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.IntegrityScopeRule;
import com.ellan.mcace.protocol.generated.DelegatedSigningKey;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.PolicyTrustStatement;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import com.ellan.mcace.protocol.generated.SignedPolicyTrustStatement;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyException;
import com.google.protobuf.ByteString;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class VerifiedPolicyCacheTest {
    private static final Instant NOW = Instant.parse("2026-08-08T08:00:00Z");
    @TempDir Path directory;
    private KeyPair keys;
    private VerifiedPolicyCache cache;

    @BeforeEach
    void setUp() throws Exception {
        keys = Ed25519Keys.generate(new SecureRandom());
        cache = new VerifiedPolicyCache(directory, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void rejectsRollbackAfterHigherSequence() throws Exception {
        cache.accept("example.test:25565", sign(2, "v2"), keys.getPublic());

        assertThrows(PolicyException.class,
                () -> cache.accept("example.test:25565", sign(1, "v1"), keys.getPublic()));
        assertEquals(2, cache.load("example.test:25565", keys.getPublic()).orElseThrow().policy().getSequence());
    }

    @Test
    void rejectsDifferentPolicyAtSameSequence() throws Exception {
        cache.accept("example.test:25565", sign(3, "v3-a"), keys.getPublic());

        assertThrows(PolicyException.class,
                () -> cache.accept("example.test:25565", sign(3, "v3-b"), keys.getPublic()));
    }

    @Test
    void rejectsOldDelegationEvenWhenOldKeySignsHigherPolicySequence() throws Exception {
        KeyPair firstDelegate = Ed25519Keys.generate(new SecureRandom());
        KeyPair secondDelegate = Ed25519Keys.generate(new SecureRandom());
        SignedPolicyTrustStatement firstTrust = trust(1, firstDelegate, null);
        SignedPolicyTrustStatement secondTrust = trust(
                2, secondDelegate, PolicyDocuments.keyId(firstDelegate.getPublic()));
        cache.accept("delegated.test", delegated(firstDelegate, firstTrust, 1), keys.getPublic());
        cache.accept("delegated.test", delegated(secondDelegate, secondTrust, 2), keys.getPublic());

        assertThrows(PolicyException.class, () -> cache.accept(
                "delegated.test", delegated(firstDelegate, firstTrust, 999), keys.getPublic()));
        assertEquals(2, cache.load("delegated.test", keys.getPublic()).orElseThrow().trustSequence());
    }

    @Test
    void rejectsConflictingRootTrustAtSameSequence() throws Exception {
        KeyPair firstDelegate = Ed25519Keys.generate(new SecureRandom());
        KeyPair secondDelegate = Ed25519Keys.generate(new SecureRandom());
        cache.accept("equivocation.test", delegated(firstDelegate, trust(5, firstDelegate, null), 5),
                keys.getPublic());

        assertThrows(PolicyException.class, () -> cache.accept(
                "equivocation.test", delegated(secondDelegate, trust(5, secondDelegate, null), 6),
                keys.getPublic()));
    }

    private SignedPolicyDocument sign(long sequence, String version) throws Exception {
        SecurityPolicy policy = SecurityPolicy.newBuilder()
                .setPolicyVersion(version).setSequence(sequence).setServerId("network")
                .setIssuedAtEpochMs(NOW.minus(Duration.ofMinutes(1)).toEpochMilli())
                .setExpiresAtEpochMs(NOW.plus(Duration.ofHours(1)).toEpochMilli())
                .setRequiredLevel(TrustLevel.VERIFIED)
                .addAllowedMinecraftVersions("1.21.1").addAllowedLoaders(LoaderType.FABRIC)
                .addIntegrityScopes(IntegrityScopeRule.newBuilder()
                        .setScope("mods").setRelativeRoot("mods").setRequired(true)
                        .setMaxEntries(8).setMaxFileBytes(1024).addAllowedExtensions(".jar"))
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(keys.getPublic())))
                .build();
        return PolicyDocuments.sign(policy, keys.getPrivate(), keys.getPublic());
    }

    private SignedPolicyTrustStatement trust(long sequence, KeyPair delegate, byte[] revoked) throws Exception {
        PolicyTrustStatement.Builder statement = PolicyTrustStatement.newBuilder()
                .setSequence(sequence).setServerId("network")
                .setIssuedAtEpochMs(NOW.minus(Duration.ofMinutes(1)).toEpochMilli())
                .setExpiresAtEpochMs(NOW.plus(Duration.ofDays(20)).toEpochMilli())
                .setRootKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(keys.getPublic())))
                .addDelegatedSigningKeys(DelegatedSigningKey.newBuilder()
                        .setKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(delegate.getPublic())))
                        .setPublicKeyX509(ByteString.copyFrom(delegate.getPublic().getEncoded()))
                        .setNotBeforeEpochMs(NOW.minus(Duration.ofMinutes(1)).toEpochMilli())
                        .setNotAfterEpochMs(NOW.plus(Duration.ofDays(10)).toEpochMilli()));
        if (revoked != null) {
            statement.addRevokedKeyIdsSha256(ByteString.copyFrom(revoked));
        }
        return PolicyDocuments.signTrustStatement(statement.build(), keys.getPrivate(), keys.getPublic());
    }

    private SignedPolicyDocument delegated(KeyPair delegate, SignedPolicyTrustStatement trust, long sequence)
            throws Exception {
        SecurityPolicy policy = SecurityPolicy.newBuilder()
                .setPolicyVersion("delegated-" + sequence).setSequence(sequence).setServerId("network")
                .setIssuedAtEpochMs(NOW.toEpochMilli())
                .setExpiresAtEpochMs(NOW.plus(Duration.ofHours(1)).toEpochMilli())
                .setRequiredLevel(TrustLevel.VERIFIED)
                .addAllowedMinecraftVersions("1.21.1").addAllowedLoaders(LoaderType.FABRIC)
                .addIntegrityScopes(IntegrityScopeRule.newBuilder()
                        .setScope("mods").setRelativeRoot("mods").setRequired(true)
                        .setMaxEntries(8).setMaxFileBytes(1024).addAllowedExtensions(".jar"))
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(delegate.getPublic())))
                .build();
        return PolicyDocuments.signDelegated(policy, delegate.getPrivate(), delegate.getPublic(), trust);
    }
}
