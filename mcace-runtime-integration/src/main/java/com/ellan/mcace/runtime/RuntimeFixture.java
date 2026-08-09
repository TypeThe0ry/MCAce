package com.ellan.mcace.runtime;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.generated.DelegatedSigningKey;
import com.ellan.mcace.protocol.generated.IntegrityScopeRule;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.PolicyTrustStatement;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyException;
import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Clock;
import java.time.Instant;

record RuntimeFixture(KeyPair serverIdentity, SignedPolicyDocument policy) {
    static RuntimeFixture create() throws EnvelopeException, PolicyException {
        return create(Clock.systemUTC());
    }

    static RuntimeFixture create(Clock clock) throws EnvelopeException, PolicyException {
        Instant now = clock.instant();
        Instant trustIssuedAt = now.minusSeconds(1);
        KeyPair root = Ed25519Keys.generate(new SecureRandom());
        KeyPair delegate = Ed25519Keys.generate(new SecureRandom());
        var trust = PolicyDocuments.signTrustStatement(PolicyTrustStatement.newBuilder()
                .setSequence(1)
                .setServerId("runtime-network")
                .setIssuedAtEpochMs(trustIssuedAt.toEpochMilli())
                .setExpiresAtEpochMs(trustIssuedAt.plus(Duration.ofDays(30)).toEpochMilli())
                .setRootKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(root.getPublic())))
                .addDelegatedSigningKeys(DelegatedSigningKey.newBuilder()
                        .setKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(delegate.getPublic())))
                        .setPublicKeyX509(ByteString.copyFrom(delegate.getPublic().getEncoded()))
                        .setNotBeforeEpochMs(now.minusSeconds(1).toEpochMilli())
                        .setNotAfterEpochMs(now.plus(Duration.ofDays(14)).toEpochMilli()))
                .build(), root.getPrivate(), root.getPublic());
        SecurityPolicy policy = SecurityPolicy.newBuilder()
                .setPolicyVersion("runtime-v1")
                .setSequence(1)
                .setServerId("runtime-network")
                .setIssuedAtEpochMs(now.toEpochMilli())
                .setExpiresAtEpochMs(now.plus(Duration.ofHours(1)).toEpochMilli())
                .setRequiredLevel(TrustLevel.VERIFIED)
                .addAllowedMinecraftVersions("1.21.1")
                .addAllowedLoaders(LoaderType.FABRIC)
                .addAllowedBuildIds("runtime-good")
                .addIntegrityScopes(IntegrityScopeRule.newBuilder()
                        .setScope("mods")
                        .setRelativeRoot("mods")
                        .setRequired(true)
                        .setMaxEntries(16)
                        .setMaxFileBytes(1024 * 1024)
                        .addAllowedExtensions(".jar"))
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(delegate.getPublic())))
                .build();
        return new RuntimeFixture(root, PolicyDocuments.signDelegated(
                policy, delegate.getPrivate(), delegate.getPublic(), trust));
    }
}
