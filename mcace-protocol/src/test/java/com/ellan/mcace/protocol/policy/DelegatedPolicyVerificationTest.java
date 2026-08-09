package com.ellan.mcace.protocol.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.DelegatedSigningKey;
import com.ellan.mcace.protocol.generated.IntegrityScopeRule;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.PolicyTrustStatement;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import com.ellan.mcace.protocol.generated.SignedPolicyTrustStatement;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

final class DelegatedPolicyVerificationTest {
    private static final Instant NOW = Instant.parse("2026-08-08T08:00:00Z");
    private KeyPair root;
    private KeyPair delegate;

    @BeforeEach
    void setUp() throws Exception {
        root = Ed25519Keys.generate(new SecureRandom());
        delegate = Ed25519Keys.generate(new SecureRandom());
    }

    @Test
    void verifiesRootAuthorizedDelegatedPolicy() throws Exception {
        SignedPolicyDocument document = delegatedPolicy(delegate, trust(7, List.of(delegate), List.of()), 11,
                NOW.plus(Duration.ofHours(1)));

        PolicyVerification verified = PolicyDocuments.verifyDetailed(
                document, root.getPublic(), Clock.fixed(NOW, ZoneOffset.UTC), Duration.ZERO);

        assertTrue(verified.delegated());
        assertEquals(7, verified.trustSequence());
        assertEquals(11, verified.policy().getSequence());
    }

    @Test
    void rejectsPolicySignedByUnlistedKey() throws Exception {
        KeyPair attacker = Ed25519Keys.generate(new SecureRandom());
        SignedPolicyDocument document = delegatedPolicy(attacker, trust(1, List.of(delegate), List.of()), 1,
                NOW.plus(Duration.ofHours(1)));

        assertThrows(PolicyException.class, () -> PolicyDocuments.verify(
                document, root.getPublic(), Clock.fixed(NOW, ZoneOffset.UTC), Duration.ZERO));
    }

    @Test
    void rejectsRevokedFormerDelegateEvenWithValidPolicySignature() throws Exception {
        SignedPolicyTrustStatement revokedTrust = trust(
                2, List.of(), List.of(ByteString.copyFrom(PolicyDocuments.keyId(delegate.getPublic()))));
        SignedPolicyDocument document = delegatedPolicy(
                delegate, revokedTrust, 99, NOW.plus(Duration.ofHours(1)));

        assertThrows(PolicyException.class, () -> PolicyDocuments.verify(
                document, root.getPublic(), Clock.fixed(NOW, ZoneOffset.UTC), Duration.ZERO));
    }

    @Test
    void rejectsPolicyWhoseLifetimeExceedsDelegation() throws Exception {
        SignedPolicyDocument document = delegatedPolicy(delegate, trust(1, List.of(delegate), List.of()), 1,
                NOW.plus(Duration.ofDays(15)));

        assertThrows(PolicyException.class, () -> PolicyDocuments.verify(
                document, root.getPublic(), Clock.fixed(NOW, ZoneOffset.UTC), Duration.ZERO));
    }

    @Test
    void rejectsTamperedRootTrustStatement() throws Exception {
        SignedPolicyDocument document = delegatedPolicy(delegate, trust(1, List.of(delegate), List.of()), 1,
                NOW.plus(Duration.ofHours(1)));
        byte[] statement = document.getTrustStatement().getStatement().toByteArray();
        statement[statement.length - 1] ^= 1;
        SignedPolicyDocument tampered = document.toBuilder().setTrustStatement(
                document.getTrustStatement().toBuilder().setStatement(ByteString.copyFrom(statement))).build();

        assertThrows(PolicyException.class, () -> PolicyDocuments.verify(
                tampered, root.getPublic(), Clock.fixed(NOW, ZoneOffset.UTC), Duration.ZERO));
    }

    private SignedPolicyTrustStatement trust(
            long sequence,
            List<KeyPair> delegates,
            List<ByteString> revoked) throws Exception {
        PolicyTrustStatement.Builder statement = PolicyTrustStatement.newBuilder()
                .setSequence(sequence).setServerId("network")
                .setIssuedAtEpochMs(NOW.toEpochMilli())
                .setExpiresAtEpochMs(NOW.plus(Duration.ofDays(30)).toEpochMilli())
                .setRootKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(root.getPublic())))
                .addAllRevokedKeyIdsSha256(revoked);
        for (KeyPair key : delegates) {
            statement.addDelegatedSigningKeys(DelegatedSigningKey.newBuilder()
                    .setKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(key.getPublic())))
                    .setPublicKeyX509(ByteString.copyFrom(key.getPublic().getEncoded()))
                    .setNotBeforeEpochMs(NOW.toEpochMilli())
                    .setNotAfterEpochMs(NOW.plus(Duration.ofDays(14)).toEpochMilli()));
        }
        return PolicyDocuments.signTrustStatement(statement.build(), root.getPrivate(), root.getPublic());
    }

    private SignedPolicyDocument delegatedPolicy(
            KeyPair signer,
            SignedPolicyTrustStatement trust,
            long sequence,
            Instant expires) throws Exception {
        SecurityPolicy policy = SecurityPolicy.newBuilder()
                .setPolicyVersion("delegated-test").setSequence(sequence).setServerId("network")
                .setIssuedAtEpochMs(NOW.toEpochMilli()).setExpiresAtEpochMs(expires.toEpochMilli())
                .setRequiredLevel(TrustLevel.VERIFIED)
                .addAllowedMinecraftVersions("1.21.1").addAllowedLoaders(LoaderType.FABRIC)
                .addIntegrityScopes(IntegrityScopeRule.newBuilder()
                        .setScope("mods").setRelativeRoot("mods").setRequired(true)
                        .setMaxEntries(8).setMaxFileBytes(1024).addAllowedExtensions(".jar"))
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(signer.getPublic())))
                .build();
        return PolicyDocuments.signDelegated(policy, signer.getPrivate(), signer.getPublic(), trust);
    }
}
