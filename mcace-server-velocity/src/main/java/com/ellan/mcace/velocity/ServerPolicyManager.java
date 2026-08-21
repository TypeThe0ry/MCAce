package com.ellan.mcace.velocity;

import com.ellan.mcace.core.policy.SignedPolicyProvider;
import com.ellan.mcace.protocol.generated.DelegatedSigningKey;
import com.ellan.mcace.protocol.generated.IntegrityScopeRule;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.PolicyTrustStatement;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import com.ellan.mcace.protocol.generated.SignedPolicyTrustStatement;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyException;
import com.ellan.mcace.protocol.policy.PolicyVerification;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

final class ServerPolicyManager implements SignedPolicyProvider {
    private static final Duration POLICY_LIFETIME = Duration.ofHours(24);
    private static final Duration POLICY_RENEW_BEFORE = Duration.ofHours(1);
    private static final Duration DELEGATE_LIFETIME = Duration.ofDays(14);
    private static final Duration DELEGATE_ROTATE_BEFORE = Duration.ofDays(2);
    private static final Duration TRUST_LIFETIME = Duration.ofDays(30);

    private final Path path;
    private final Path keyDirectory;
    private final Clock clock;
    private final KeyPair rootIdentity;
    private final SecureRandom random;
    private final VelocityAdmissionConfig.PolicyConfig policyConfiguration;

    ServerPolicyManager(Path path, Clock clock, KeyPair rootIdentity) {
        this(path, clock, rootIdentity, new SecureRandom(), defaultPolicyConfiguration());
    }

    ServerPolicyManager(Path path, Clock clock, KeyPair rootIdentity, SecureRandom random) {
        this(path, clock, rootIdentity, random, defaultPolicyConfiguration());
    }

    ServerPolicyManager(
            Path path,
            Clock clock,
            KeyPair rootIdentity,
            VelocityAdmissionConfig.PolicyConfig policyConfiguration) {
        this(path, clock, rootIdentity, new SecureRandom(), policyConfiguration);
    }

    ServerPolicyManager(
            Path path,
            Clock clock,
            KeyPair rootIdentity,
            SecureRandom random,
            VelocityAdmissionConfig.PolicyConfig policyConfiguration) {
        this.path = path.toAbsolutePath().normalize();
        this.keyDirectory = this.path.getParent().resolve("delegated-key");
        this.clock = clock;
        this.rootIdentity = rootIdentity;
        this.random = random;
        this.policyConfiguration = policyConfiguration;
    }

    @Override
    public synchronized SignedPolicyDocument current() throws PolicyException {
        return issue(false);
    }

    synchronized SignedPolicyDocument rotateDelegatedKey() throws PolicyException {
        return issue(true);
    }

    private SignedPolicyDocument issue(boolean forceRotation) throws PolicyException {
        SignedPolicyDocument previous = read();
        PolicyVerification previousVerification = previous == null
                ? null
                : PolicyDocuments.verifySignatureAndStructureDetailed(previous, rootIdentity.getPublic());
        long now = clock.millis();
        long policySequence = previousVerification == null
                ? 1
                : increment(previousVerification.policy().getSequence(), "policy sequence");
        KeyPair delegate = DelegatedPolicyKeyStore.load(keyDirectory).orElse(null);
        DelegatedSigningKey currentAuthorization = previousVerification != null && previousVerification.delegated()
                ? findAuthorization(previous)
                : null;
        boolean releaseConfigurationChanged = previousVerification != null
                && !matchesReleaseConfiguration(previousVerification.policy());
        boolean trustConfigurationChanged = previous != null && previous.hasTrustStatement()
                && !trustMatchesServerId(previous.getTrustStatement());

        boolean rotate = forceRotation
                || trustConfigurationChanged
                || delegate == null
                || currentAuthorization == null
                || currentAuthorization.getNotAfterEpochMs() <= now + DELEGATE_ROTATE_BEFORE.toMillis()
                || !java.security.MessageDigest.isEqual(
                        PolicyDocuments.keyId(delegate.getPublic()),
                        previousVerification.signerKeyIdSha256());

        if (!rotate && !releaseConfigurationChanged
                && previousVerification.policy().getExpiresAtEpochMs() > now + POLICY_RENEW_BEFORE.toMillis()) {
            PolicyDocuments.verify(previous, rootIdentity.getPublic(), clock, Duration.ofSeconds(30));
            return previous;
        }

        SignedPolicyTrustStatement trust;
        if (rotate) {
            byte[] oldSigner = previousVerification != null && previousVerification.delegated()
                    ? previousVerification.signerKeyIdSha256()
                    : null;
            delegate = DelegatedPolicyKeyStore.rotate(keyDirectory, random);
            trust = newTrustStatement(previous, delegate, oldSigner, now);
        } else {
            trust = previous.getTrustStatement();
        }
        SecurityPolicy policy = buildPolicy(policySequence, now, delegate, currentDelegate(trust));
        SignedPolicyDocument document = PolicyDocuments.signDelegated(
                policy, delegate.getPrivate(), delegate.getPublic(), trust);
        PolicyDocuments.verify(document, rootIdentity.getPublic(), clock, Duration.ofSeconds(30));
        write(document);
        return document;
    }

    private SignedPolicyTrustStatement newTrustStatement(
            SignedPolicyDocument previous,
            KeyPair delegate,
            byte[] oldSigner,
            long now) throws PolicyException {
        long trustSequence = 1;
        List<ByteString> revoked = new ArrayList<>();
        if (previous != null && previous.hasTrustStatement()) {
            PolicyVerification verification = PolicyDocuments.verifySignatureAndStructureDetailed(
                    previous, rootIdentity.getPublic());
            trustSequence = increment(verification.trustSequence(), "trust sequence");
            try {
                PolicyTrustStatement oldTrust = PolicyTrustStatement.parseFrom(
                        previous.getTrustStatement().getStatement());
                revoked.addAll(oldTrust.getRevokedKeyIdsSha256List());
            } catch (com.google.protobuf.InvalidProtocolBufferException exception) {
                throw new PolicyException("cannot parse previous trust statement", exception);
            }
        }
        if (oldSigner != null && revoked.stream().noneMatch(id ->
                java.security.MessageDigest.isEqual(id.toByteArray(), oldSigner))) {
            revoked.add(ByteString.copyFrom(oldSigner));
        }
        byte[] delegateId = PolicyDocuments.keyId(delegate.getPublic());
        PolicyTrustStatement statement = PolicyTrustStatement.newBuilder()
                .setSequence(trustSequence)
                .setServerId(policyConfiguration.serverId())
                .setIssuedAtEpochMs(now)
                .setExpiresAtEpochMs(now + TRUST_LIFETIME.toMillis())
                .setRootKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(rootIdentity.getPublic())))
                .addDelegatedSigningKeys(DelegatedSigningKey.newBuilder()
                        .setKeyIdSha256(ByteString.copyFrom(delegateId))
                        .setPublicKeyX509(ByteString.copyFrom(delegate.getPublic().getEncoded()))
                        .setNotBeforeEpochMs(now)
                        .setNotAfterEpochMs(now + DELEGATE_LIFETIME.toMillis()))
                .addAllRevokedKeyIdsSha256(revoked)
                .build();
        return PolicyDocuments.signTrustStatement(statement, rootIdentity.getPrivate(), rootIdentity.getPublic());
    }

    private SecurityPolicy buildPolicy(
            long sequence,
            long now,
            KeyPair delegate,
            DelegatedSigningKey authorization) throws PolicyException {
        long expiresAt = Math.min(now + POLICY_LIFETIME.toMillis(), authorization.getNotAfterEpochMs());
        return SecurityPolicy.newBuilder()
                .setPolicyVersion("phase2-v3")
                .setSequence(sequence)
                .setServerId(policyConfiguration.serverId())
                .setIssuedAtEpochMs(now)
                .setExpiresAtEpochMs(expiresAt)
                .setRequiredLevel(TrustLevel.VERIFIED)
                .addAllAllowedMinecraftVersions(policyConfiguration.minecraftVersions())
                .addAllowedLoaders(LoaderType.FABRIC)
                .addAllAllowedBuildIds(policyConfiguration.clientBuildIds())
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(delegate.getPublic())))
                .addIntegrityScopes(directory("mods", true, "mods", 4096, 512L * 1024 * 1024,
                        List.of(".jar", ".disabled")))
                .addIntegrityScopes(directory("resourcepacks", false, "resourcepacks", 4096, 1024L * 1024 * 1024,
                        List.of(".zip", ".jar", ".json", ".png", ".mcmeta")))
                .addIntegrityScopes(directory("shaderpacks", false, "shaderpacks", 4096, 1024L * 1024 * 1024,
                        List.of(".zip", ".jar", ".json", ".properties", ".txt", ".glsl", ".vsh", ".fsh")))
                .addIntegrityScopes(IntegrityScopeRule.newBuilder()
                        .setScope("config").setRequired(false).setMaxEntries(1)
                        .setMaxFileBytes(16L * 1024 * 1024).addAllowedExtensions(".txt")
                        .addExplicitRelativeFiles("options.txt"))
                .build();
    }

    private static VelocityAdmissionConfig.PolicyConfig defaultPolicyConfiguration() {
        return new VelocityAdmissionConfig.PolicyConfig(
                "mcace-velocity", List.of("1.21.11"), List.of("fabric-phase2-dev"));
    }

    private boolean matchesReleaseConfiguration(SecurityPolicy policy) {
        return policyConfiguration.serverId().equals(policy.getServerId())
                && policyConfiguration.minecraftVersions().equals(policy.getAllowedMinecraftVersionsList())
                && policyConfiguration.clientBuildIds().equals(policy.getAllowedBuildIdsList())
                && policy.getAllowedLoadersList().equals(List.of(LoaderType.FABRIC));
    }

    private boolean trustMatchesServerId(SignedPolicyTrustStatement signed) throws PolicyException {
        try {
            return policyConfiguration.serverId().equals(
                    PolicyTrustStatement.parseFrom(signed.getStatement()).getServerId());
        } catch (com.google.protobuf.InvalidProtocolBufferException exception) {
            throw new PolicyException("cannot parse policy trust statement", exception);
        }
    }

    private static DelegatedSigningKey currentDelegate(SignedPolicyTrustStatement signed) throws PolicyException {
        try {
            PolicyTrustStatement trust = PolicyTrustStatement.parseFrom(signed.getStatement());
            if (trust.getDelegatedSigningKeysCount() != 1) {
                throw new PolicyException("server trust statement must authorize exactly one active key");
            }
            return trust.getDelegatedSigningKeys(0);
        } catch (com.google.protobuf.InvalidProtocolBufferException exception) {
            throw new PolicyException("cannot parse policy trust statement", exception);
        }
    }

    private static DelegatedSigningKey findAuthorization(SignedPolicyDocument document) throws PolicyException {
        DelegatedSigningKey authorization = currentDelegate(document.getTrustStatement());
        if (!java.security.MessageDigest.isEqual(
                authorization.getKeyIdSha256().toByteArray(),
                document.getSignerKeyIdSha256().toByteArray())) {
            throw new PolicyException("persisted policy signer is not the active delegated key");
        }
        return authorization;
    }

    private static long increment(long value, String name) throws PolicyException {
        try {
            return Math.addExact(value, 1);
        } catch (ArithmeticException exception) {
            throw new PolicyException(name + " overflow", exception);
        }
    }

    private static IntegrityScopeRule directory(
            String scope, boolean required, String root, int maxEntries, long maxBytes, List<String> extensions) {
        return IntegrityScopeRule.newBuilder().setScope(scope).setRequired(required).setRelativeRoot(root)
                .setMaxEntries(maxEntries).setMaxFileBytes(maxBytes).addAllAllowedExtensions(extensions).build();
    }

    private SignedPolicyDocument read() throws PolicyException {
        if (!Files.exists(path)) return null;
        try {
            return SignedPolicyDocument.parseFrom(Files.readAllBytes(path));
        } catch (IOException exception) {
            throw new PolicyException("cannot read persisted server policy", exception);
        }
    }

    private void write(SignedPolicyDocument document) throws PolicyException {
        try {
            Files.createDirectories(path.getParent());
            Path temporary = Files.createTempFile(path.getParent(), path.getFileName().toString(), ".tmp");
            try {
                Files.write(temporary, document.toByteArray());
                try {
                    Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException exception) {
                    Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING);
                }
            } finally {
                Files.deleteIfExists(temporary);
            }
        } catch (IOException exception) {
            throw new PolicyException("cannot persist signed server policy", exception);
        }
    }
}
