package com.ellan.mcace.protocol.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.IntegrityScopeRule;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

final class PolicyDocumentsTest {
    private static final Instant NOW = Instant.parse("2026-08-08T08:00:00Z");
    private KeyPair keys;

    @BeforeEach
    void setUp() throws Exception {
        keys = Ed25519Keys.generate(new SecureRandom());
    }

    @Test
    void signsAndVerifiesCurrentPolicy() throws Exception {
        SignedPolicyDocument document = sign(policy(1, "phase2-test"));

        SecurityPolicy verified = PolicyDocuments.verify(
                document, keys.getPublic(), Clock.fixed(NOW, ZoneOffset.UTC), Duration.ZERO);

        assertEquals(1, verified.getSequence());
    }

    @Test
    void rejectsTamperedPolicyBody() throws Exception {
        SignedPolicyDocument document = sign(policy(1, "phase2-test"));
        byte[] body = document.getPolicy().toByteArray();
        body[body.length - 1] ^= 1;
        SignedPolicyDocument tampered = document.toBuilder().setPolicy(ByteString.copyFrom(body)).build();

        assertThrows(PolicyException.class, () -> PolicyDocuments.verify(
                tampered, keys.getPublic(), Clock.fixed(NOW, ZoneOffset.UTC), Duration.ZERO));
    }

    @Test
    void rejectsExpiredPolicy() throws Exception {
        SignedPolicyDocument document = sign(policy(1, "phase2-test"));
        Clock later = Clock.fixed(NOW.plus(Duration.ofHours(2)), ZoneOffset.UTC);

        assertThrows(PolicyException.class,
                () -> PolicyDocuments.verify(document, keys.getPublic(), later, Duration.ZERO));
    }

    @Test
    void rejectsUnsafeDirectoryScopeBeforeSigning() throws Exception {
        SecurityPolicy unsafe = policy(1, "phase2-test").toBuilder()
                .clearIntegrityScopes()
                .addIntegrityScopes(IntegrityScopeRule.newBuilder()
                        .setScope("escape").setRelativeRoot("../private").setRequired(true)
                        .setMaxEntries(1).setMaxFileBytes(1024).addAllowedExtensions(".txt"))
                .build();

        assertThrows(PolicyException.class, () -> sign(unsafe));
    }

    private SignedPolicyDocument sign(SecurityPolicy policy) throws Exception {
        return PolicyDocuments.sign(policy, keys.getPrivate(), keys.getPublic());
    }

    private SecurityPolicy policy(long sequence, String version) throws Exception {
        return SecurityPolicy.newBuilder()
                .setPolicyVersion(version)
                .setSequence(sequence)
                .setServerId("test-network")
                .setIssuedAtEpochMs(NOW.toEpochMilli())
                .setExpiresAtEpochMs(NOW.plus(Duration.ofHours(1)).toEpochMilli())
                .setRequiredLevel(TrustLevel.VERIFIED)
                .addAllowedMinecraftVersions("1.21.1")
                .addAllowedLoaders(LoaderType.FABRIC)
                .addIntegrityScopes(IntegrityScopeRule.newBuilder()
                        .setScope("mods").setRelativeRoot("mods").setRequired(true)
                        .setMaxEntries(16).setMaxFileBytes(1024 * 1024).addAllowedExtensions(".jar"))
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(keys.getPublic())))
                .build();
    }
}
