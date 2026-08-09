package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import com.ellan.mcace.protocol.generated.PolicyTrustStatement;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyVerification;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class ServerPolicyManagerTest {
    @TempDir Path directory;

    @Test
    void persistsAndRenewsSignedPolicyWithIncreasingSequence() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-08T08:00:00Z"));
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        Path path = directory.resolve("policy").resolve("signed-policy.pb");
        ServerPolicyManager manager = new ServerPolicyManager(path, clock, identity);

        SignedPolicyDocument first = manager.current();
        assertEquals(first, manager.current());
        assertTrue(Files.isRegularFile(path));
        PolicyVerification firstVerification = PolicyDocuments.verifyDetailed(
                first, identity.getPublic(), clock, Duration.ofSeconds(1));
        assertTrue(firstVerification.delegated());
        assertEquals(1, firstVerification.trustSequence());

        clock.advance(Duration.ofHours(24));
        SignedPolicyDocument renewed = manager.current();
        SecurityPolicy policy = PolicyDocuments.verify(
                renewed, identity.getPublic(), clock, Duration.ofSeconds(1));

        assertEquals(2, policy.getSequence());
        assertEquals(4, policy.getIntegrityScopesCount());
    }

    @Test
    void forcedRotationRevokesOldDelegateAndAdvancesBothSequences() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-08T08:00:00Z"));
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        ServerPolicyManager manager = new ServerPolicyManager(
                directory.resolve("policy").resolve("signed-policy.pb"), clock, identity);
        SignedPolicyDocument first = manager.current();
        byte[] oldSigner = first.getSignerKeyIdSha256().toByteArray();

        clock.advance(Duration.ofMinutes(1));
        SignedPolicyDocument rotated = manager.rotateDelegatedKey();
        PolicyVerification verified = PolicyDocuments.verifyDetailed(
                rotated, identity.getPublic(), clock, Duration.ofSeconds(1));
        PolicyTrustStatement trust = PolicyTrustStatement.parseFrom(rotated.getTrustStatement().getStatement());

        assertEquals(2, verified.policy().getSequence());
        assertEquals(2, verified.trustSequence());
        assertTrue(trust.getRevokedKeyIdsSha256List().stream().anyMatch(id ->
                java.security.MessageDigest.isEqual(id.toByteArray(), oldSigner)));
        assertTrue(!java.security.MessageDigest.isEqual(oldSigner, verified.signerKeyIdSha256()));
    }

    @Test
    void signsConfiguredNetworkAndFabricReleaseMetadata() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-08T08:00:00Z"));
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        VelocityAdmissionConfig.PolicyConfig configuration = new VelocityAdmissionConfig.PolicyConfig(
                "network-east", List.of("1.21.1", "1.21.4"),
                List.of("fabric-release-17", "fabric-release-18"));
        ServerPolicyManager manager = new ServerPolicyManager(
                directory.resolve("configured").resolve("signed-policy.pb"),
                clock,
                identity,
                configuration);

        SecurityPolicy policy = PolicyDocuments.verify(
                manager.current(), identity.getPublic(), clock, Duration.ofSeconds(1));
        PolicyTrustStatement trust = PolicyTrustStatement.parseFrom(
                manager.current().getTrustStatement().getStatement());

        assertEquals("network-east", policy.getServerId());
        assertEquals(List.of("1.21.1", "1.21.4"), policy.getAllowedMinecraftVersionsList());
        assertEquals(List.of("fabric-release-17", "fabric-release-18"), policy.getAllowedBuildIdsList());
        assertEquals("network-east", trust.getServerId());
    }

    @Test
    void configurationChangeImmediatelyPublishesANewChainedPolicy() throws Exception {
        MutableClock clock = new MutableClock(Instant.parse("2026-08-08T08:00:00Z"));
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        Path path = directory.resolve("reconfigured").resolve("signed-policy.pb");
        SignedPolicyDocument first = new ServerPolicyManager(path, clock, identity).current();

        VelocityAdmissionConfig.PolicyConfig replacement = new VelocityAdmissionConfig.PolicyConfig(
                "network-west", List.of("1.21.1"), List.of("fabric-release-19"));
        ServerPolicyManager reconfigured = new ServerPolicyManager(path, clock, identity, replacement);
        SignedPolicyDocument second = reconfigured.current();
        PolicyVerification verified = PolicyDocuments.verifyDetailed(
                second, identity.getPublic(), clock, Duration.ofSeconds(1));

        assertEquals(2, verified.policy().getSequence());
        assertEquals(2, verified.trustSequence());
        assertEquals("network-west", verified.policy().getServerId());
        assertEquals(List.of("fabric-release-19"), verified.policy().getAllowedBuildIdsList());
        assertTrue(!java.security.MessageDigest.isEqual(
                first.getSignerKeyIdSha256().toByteArray(), second.getSignerKeyIdSha256().toByteArray()));
    }

    private static final class MutableClock extends Clock {
        private Instant instant;

        private MutableClock(Instant instant) {
            this.instant = instant;
        }

        private void advance(Duration duration) {
            instant = instant.plus(duration);
        }

        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return instant; }
    }
}
