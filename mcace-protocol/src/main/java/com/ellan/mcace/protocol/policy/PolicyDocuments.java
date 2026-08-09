package com.ellan.mcace.protocol.policy;

import com.ellan.mcace.protocol.generated.DelegatedSigningKey;
import com.ellan.mcace.protocol.generated.IntegrityScopeRule;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.PolicyTrustStatement;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import com.ellan.mcace.protocol.generated.SignedPolicyTrustStatement;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.HashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

public final class PolicyDocuments {
    private static final byte[] SIGNATURE_DOMAIN = "mcace-policy-v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] TRUST_SIGNATURE_DOMAIN =
            "mcace-policy-trust-v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final Duration MAX_POLICY_LIFETIME = Duration.ofDays(30);
    private static final int MAX_SCOPES = 32;
    private static final int MAX_EXPLICIT_FILES = 128;
    private static final int MAX_DELEGATED_KEYS = 16;
    private static final int MAX_REVOKED_KEYS = 512;

    private PolicyDocuments() {
    }

    public static SignedPolicyDocument sign(SecurityPolicy policy, PrivateKey privateKey, PublicKey publicKey)
            throws PolicyException {
        return signInternal(policy, privateKey, publicKey, null);
    }

    public static SignedPolicyDocument signDelegated(
            SecurityPolicy policy,
            PrivateKey privateKey,
            PublicKey publicKey,
            SignedPolicyTrustStatement trustStatement) throws PolicyException {
        Objects.requireNonNull(trustStatement, "trustStatement");
        return signInternal(policy, privateKey, publicKey, trustStatement);
    }

    private static SignedPolicyDocument signInternal(
            SecurityPolicy policy,
            PrivateKey privateKey,
            PublicKey publicKey,
            SignedPolicyTrustStatement trustStatement) throws PolicyException {
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(publicKey, "publicKey");
        byte[] keyId = keyId(publicKey);
        if (!MessageDigest.isEqual(keyId, policy.getSignerKeyIdSha256().toByteArray())) {
            throw new PolicyException("policy signer key id does not match signing key");
        }
        validateStructure(policy);
        byte[] policyBytes = policy.toByteArray();
        SignedPolicyDocument.Builder document = SignedPolicyDocument.newBuilder()
                .setPolicy(ByteString.copyFrom(policyBytes))
                .setSignerKeyIdSha256(ByteString.copyFrom(keyId))
                .setSignature(ByteString.copyFrom(sign(signingBytes(policyBytes), privateKey)));
        if (trustStatement != null) {
            document.setTrustStatement(trustStatement);
        }
        return document.build();
    }

    public static SignedPolicyTrustStatement signTrustStatement(
            PolicyTrustStatement statement,
            PrivateKey rootPrivateKey,
            PublicKey rootPublicKey) throws PolicyException {
        Objects.requireNonNull(statement, "statement");
        Objects.requireNonNull(rootPrivateKey, "rootPrivateKey");
        Objects.requireNonNull(rootPublicKey, "rootPublicKey");
        byte[] rootId = keyId(rootPublicKey);
        if (!MessageDigest.isEqual(rootId, statement.getRootKeyIdSha256().toByteArray())) {
            throw new PolicyException("trust statement root key id does not match signing key");
        }
        validateTrustStructure(statement, rootId);
        byte[] body = statement.toByteArray();
        return SignedPolicyTrustStatement.newBuilder()
                .setStatement(ByteString.copyFrom(body))
                .setRootKeyIdSha256(ByteString.copyFrom(rootId))
                .setSignature(ByteString.copyFrom(sign(trustSigningBytes(body), rootPrivateKey)))
                .build();
    }

    public static SecurityPolicy verify(
            SignedPolicyDocument document,
            PublicKey trustedKey,
            Clock clock,
            Duration allowedClockSkew) throws PolicyException {
        return verifyDetailed(document, trustedKey, clock, allowedClockSkew).policy();
    }

    public static PolicyVerification verifyDetailed(
            SignedPolicyDocument document,
            PublicKey trustedKey,
            Clock clock,
            Duration allowedClockSkew) throws PolicyException {
        PolicyVerification verification = verifySignatureAndStructureDetailed(document, trustedKey);
        SecurityPolicy policy = verification.policy();
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(allowedClockSkew, "allowedClockSkew");
        if (allowedClockSkew.isNegative()) {
            throw new PolicyException("allowed clock skew must not be negative");
        }
        long now = clock.millis();
        long skew = allowedClockSkew.toMillis();
        if (policy.getIssuedAtEpochMs() > safeAdd(now, skew)) {
            throw new PolicyException("policy was issued in the future");
        }
        if (policy.getExpiresAtEpochMs() <= safeSubtract(now, skew)) {
            throw new PolicyException("policy has expired");
        }
        if (verification.delegated()) {
            PolicyTrustStatement trust = parseAndVerifyTrust(document.getTrustStatement(), trustedKey);
            if (trust.getIssuedAtEpochMs() > safeAdd(now, skew)) {
                throw new PolicyException("policy trust statement was issued in the future");
            }
            if (trust.getExpiresAtEpochMs() <= safeSubtract(now, skew)) {
                throw new PolicyException("policy trust statement has expired");
            }
        }
        return verification;
    }

    public static SecurityPolicy verifySignatureAndStructure(
            SignedPolicyDocument document,
            PublicKey trustedKey) throws PolicyException {
        return verifySignatureAndStructureDetailed(document, trustedKey).policy();
    }

    public static PolicyVerification verifySignatureAndStructureDetailed(
            SignedPolicyDocument document,
            PublicKey trustedKey) throws PolicyException {
        Objects.requireNonNull(document, "document");
        Objects.requireNonNull(trustedKey, "trustedKey");
        if (document.getPolicy().isEmpty() || document.getSignature().isEmpty()
                || document.getSignerKeyIdSha256().size() != 32) {
            throw new PolicyException("policy document fields are missing");
        }
        byte[] rootKeyId = keyId(trustedKey);
        byte[] signerKeyId = document.getSignerKeyIdSha256().toByteArray();
        boolean delegated = !MessageDigest.isEqual(rootKeyId, signerKeyId);
        PublicKey signingKey = trustedKey;
        long trustSequence = 0;
        PolicyTrustStatement trust = null;
        DelegatedSigningKey delegatedKey = null;
        if (delegated) {
            if (!document.hasTrustStatement()) {
                throw new PolicyException("delegated policy is missing its root trust statement");
            }
            trust = parseAndVerifyTrust(document.getTrustStatement(), trustedKey);
            trustSequence = trust.getSequence();
            for (ByteString revoked : trust.getRevokedKeyIdsSha256List()) {
                if (MessageDigest.isEqual(signerKeyId, revoked.toByteArray())) {
                    throw new PolicyException("policy signer has been revoked");
                }
            }
            for (DelegatedSigningKey candidate : trust.getDelegatedSigningKeysList()) {
                if (MessageDigest.isEqual(signerKeyId, candidate.getKeyIdSha256().toByteArray())) {
                    delegatedKey = candidate;
                    break;
                }
            }
            if (delegatedKey == null) {
                throw new PolicyException("policy signer is not authorized by the pinned root");
            }
            signingKey = decodePublic(delegatedKey.getPublicKeyX509().toByteArray());
        } else if (document.hasTrustStatement()) {
            throw new PolicyException("root-signed policy must not embed delegated trust state");
        }
        if (!verifySignature(signingBytes(document.getPolicy().toByteArray()),
                document.getSignature().toByteArray(), signingKey)) {
            throw new PolicyException("invalid policy signature");
        }
        SecurityPolicy policy;
        try {
            policy = SecurityPolicy.parseFrom(document.getPolicy());
        } catch (InvalidProtocolBufferException exception) {
            throw new PolicyException("malformed policy protobuf", exception);
        }
        validateStructure(policy);
        if (!MessageDigest.isEqual(signerKeyId, policy.getSignerKeyIdSha256().toByteArray())) {
            throw new PolicyException("policy body signer key id mismatch");
        }
        long lifetime;
        try {
            lifetime = Math.subtractExact(policy.getExpiresAtEpochMs(), policy.getIssuedAtEpochMs());
        } catch (ArithmeticException exception) {
            throw new PolicyException("invalid policy lifetime", exception);
        }
        if (lifetime <= 0 || lifetime > MAX_POLICY_LIFETIME.toMillis()) {
            throw new PolicyException("policy lifetime is outside the allowed range");
        }
        for (ByteString revoked : policy.getRevokedKeyIdsSha256List()) {
            if (MessageDigest.isEqual(signerKeyId, revoked.toByteArray())) {
                throw new PolicyException("policy revokes its own signer");
            }
        }
        if (delegated) {
            if (!trust.getServerId().equals(policy.getServerId())
                    || policy.getDelegatedSigningKeysCount() != 0
                    || policy.getRevokedKeyIdsSha256Count() != 0
                    || policy.getIssuedAtEpochMs() < delegatedKey.getNotBeforeEpochMs()
                    || policy.getExpiresAtEpochMs() > delegatedKey.getNotAfterEpochMs()) {
                throw new PolicyException("delegated policy exceeds its root authorization");
            }
        }
        return new PolicyVerification(policy, trustSequence, delegated, signerKeyId);
    }

    public static byte[] keyId(PublicKey publicKey) throws PolicyException {
        Objects.requireNonNull(publicKey, "publicKey");
        return sha256(publicKey.getEncoded());
    }

    public static byte[] policyDigest(SignedPolicyDocument document) throws PolicyException {
        Objects.requireNonNull(document, "document");
        if (document.getPolicy().isEmpty()) {
            throw new PolicyException("policy document is empty");
        }
        return sha256(document.getPolicy().toByteArray());
    }

    private static PolicyTrustStatement parseAndVerifyTrust(
            SignedPolicyTrustStatement signed,
            PublicKey rootKey) throws PolicyException {
        byte[] rootId = keyId(rootKey);
        if (signed.getStatement().isEmpty()
                || signed.getSignature().isEmpty()
                || !MessageDigest.isEqual(rootId, signed.getRootKeyIdSha256().toByteArray())
                || !verifySignature(
                        trustSigningBytes(signed.getStatement().toByteArray()),
                        signed.getSignature().toByteArray(),
                        rootKey)) {
            throw new PolicyException("invalid policy trust statement signature");
        }
        PolicyTrustStatement statement;
        try {
            statement = PolicyTrustStatement.parseFrom(signed.getStatement());
        } catch (InvalidProtocolBufferException exception) {
            throw new PolicyException("malformed policy trust statement", exception);
        }
        validateTrustStructure(statement, rootId);
        return statement;
    }

    private static void validateTrustStructure(PolicyTrustStatement statement, byte[] rootId)
            throws PolicyException {
        if (statement.getSequence() <= 0
                || statement.getServerId().isBlank()
                || !MessageDigest.isEqual(rootId, statement.getRootKeyIdSha256().toByteArray())) {
            throw new PolicyException("policy trust identity fields are invalid");
        }
        long lifetime;
        try {
            lifetime = Math.subtractExact(statement.getExpiresAtEpochMs(), statement.getIssuedAtEpochMs());
        } catch (ArithmeticException exception) {
            throw new PolicyException("invalid policy trust lifetime", exception);
        }
        if (lifetime <= 0 || lifetime > MAX_POLICY_LIFETIME.toMillis()
                || statement.getDelegatedSigningKeysCount() > MAX_DELEGATED_KEYS
                || statement.getRevokedKeyIdsSha256Count() > MAX_REVOKED_KEYS) {
            throw new PolicyException("policy trust lifetime or key count is invalid");
        }
        Set<ByteString> delegatedIds = new HashSet<>();
        for (DelegatedSigningKey delegated : statement.getDelegatedSigningKeysList()) {
            if (delegated.getKeyIdSha256().size() != 32
                    || delegated.getPublicKeyX509().isEmpty()
                    || delegated.getNotAfterEpochMs() <= delegated.getNotBeforeEpochMs()
                    || delegated.getNotBeforeEpochMs() < statement.getIssuedAtEpochMs()
                    || delegated.getNotAfterEpochMs() > statement.getExpiresAtEpochMs()
                    || !delegatedIds.add(delegated.getKeyIdSha256())) {
                throw new PolicyException("invalid delegated signing key authorization");
            }
            PublicKey decoded = decodePublic(delegated.getPublicKeyX509().toByteArray());
            if (!MessageDigest.isEqual(keyId(decoded), delegated.getKeyIdSha256().toByteArray())) {
                throw new PolicyException("delegated signing key id does not match public key");
            }
        }
        Set<ByteString> revokedIds = new HashSet<>();
        for (ByteString revoked : statement.getRevokedKeyIdsSha256List()) {
            if (revoked.size() != 32
                    || MessageDigest.isEqual(rootId, revoked.toByteArray())
                    || delegatedIds.contains(revoked)
                    || !revokedIds.add(revoked)) {
                throw new PolicyException("invalid or conflicting revoked key id");
            }
        }
    }

    private static void validateStructure(SecurityPolicy policy) throws PolicyException {
        if (policy.getPolicyVersion().isBlank() || policy.getServerId().isBlank() || policy.getSequence() <= 0) {
            throw new PolicyException("policy identity fields are missing");
        }
        if (policy.getSignerKeyIdSha256().size() != 32) {
            throw new PolicyException("policy signer key id must be SHA-256");
        }
        if (policy.getRequiredLevel() == TrustLevel.UNKNOWN
                || policy.getRequiredLevel() == TrustLevel.UNRECOGNIZED) {
            throw new PolicyException("policy trust level is invalid");
        }
        if (policy.getAllowedMinecraftVersionsCount() == 0 || policy.getAllowedLoadersCount() == 0) {
            throw new PolicyException("policy compatibility lists must not be empty");
        }
        if (policy.getAllowedLoadersList().stream()
                .anyMatch(loader -> loader == LoaderType.LOADER_UNSPECIFIED || loader == LoaderType.UNRECOGNIZED)) {
            throw new PolicyException("policy contains an invalid loader");
        }
        if (policy.getIntegrityScopesCount() == 0 || policy.getIntegrityScopesCount() > MAX_SCOPES) {
            throw new PolicyException("policy scope count is invalid");
        }
        Set<String> names = new HashSet<>();
        for (IntegrityScopeRule rule : policy.getIntegrityScopesList()) {
            validateRule(rule, names);
        }
        Set<ByteString> delegatedIds = new HashSet<>();
        for (DelegatedSigningKey delegated : policy.getDelegatedSigningKeysList()) {
            if (delegated.getKeyIdSha256().size() != 32
                    || delegated.getPublicKeyX509().isEmpty()
                    || delegated.getNotAfterEpochMs() <= delegated.getNotBeforeEpochMs()
                    || !delegatedIds.add(delegated.getKeyIdSha256())) {
                throw new PolicyException("invalid delegated signing key");
            }
        }
        if (policy.getRevokedKeyIdsSha256List().stream().anyMatch(id -> id.size() != 32)) {
            throw new PolicyException("revoked key ids must be SHA-256");
        }
    }

    private static void validateRule(IntegrityScopeRule rule, Set<String> names) throws PolicyException {
        String scope = rule.getScope().trim().toLowerCase(Locale.ROOT);
        if (!scope.matches("[a-z0-9][a-z0-9_-]{0,31}") || !names.add(scope)) {
            throw new PolicyException("invalid or duplicate integrity scope name");
        }
        if (rule.getMaxEntries() <= 0 || rule.getMaxEntries() > 4096
                || rule.getMaxFileBytes() <= 0 || rule.getMaxFileBytes() > 1024L * 1024 * 1024) {
            throw new PolicyException("integrity scope ceilings are invalid");
        }
        boolean directory = !rule.getRelativeRoot().isBlank();
        boolean explicit = rule.getExplicitRelativeFilesCount() > 0;
        if (directory == explicit || rule.getExplicitRelativeFilesCount() > MAX_EXPLICIT_FILES) {
            throw new PolicyException("scope must select one directory root or explicit file list");
        }
        if (directory) {
            validateRelativePath(rule.getRelativeRoot());
            if (rule.getAllowedExtensionsCount() == 0) {
                throw new PolicyException("directory scopes require an extension allowlist");
            }
        } else {
            Set<String> explicitPaths = new HashSet<>();
            for (String path : rule.getExplicitRelativeFilesList()) {
                validateRelativePath(path);
                if (!explicitPaths.add(path)) {
                    throw new PolicyException("explicit scope contains duplicate paths");
                }
            }
        }
        if (rule.getAllowedExtensionsCount() > 32
                || rule.getAllowedExtensionsList().stream()
                .anyMatch(extension -> !extension.matches("\\.[a-z0-9._-]{1,15}"))) {
            throw new PolicyException("invalid allowed extension");
        }
    }

    private static void validateRelativePath(String path) throws PolicyException {
        if (path.isBlank()
                || path.startsWith("/")
                || path.contains("\\")
                || path.contains(":")
                || path.equals("..")
                || path.startsWith("../")
                || path.endsWith("/..")
                || path.contains("/../")) {
            throw new PolicyException("policy path is not a safe relative path: " + path);
        }
    }

    private static byte[] signingBytes(byte[] policy) {
        return ByteBuffer.allocate(SIGNATURE_DOMAIN.length + Integer.BYTES + policy.length)
                .put(SIGNATURE_DOMAIN)
                .putInt(policy.length)
                .put(policy)
                .array();
    }

    private static byte[] trustSigningBytes(byte[] statement) {
        return ByteBuffer.allocate(TRUST_SIGNATURE_DOMAIN.length + Integer.BYTES + statement.length)
                .put(TRUST_SIGNATURE_DOMAIN)
                .putInt(statement.length)
                .put(statement)
                .array();
    }

    private static byte[] sign(byte[] content, PrivateKey privateKey) throws PolicyException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey);
            signature.update(content);
            return signature.sign();
        } catch (GeneralSecurityException exception) {
            throw new PolicyException("failed to sign policy", exception);
        }
    }

    private static boolean verifySignature(byte[] content, byte[] signed, PublicKey publicKey) throws PolicyException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(publicKey);
            signature.update(content);
            return signature.verify(signed);
        } catch (GeneralSecurityException exception) {
            throw new PolicyException("failed to verify policy", exception);
        }
    }

    private static PublicKey decodePublic(byte[] encoded) throws PolicyException {
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));
        } catch (GeneralSecurityException exception) {
            throw new PolicyException("invalid delegated Ed25519 public key", exception);
        }
    }

    private static byte[] sha256(byte[] content) throws PolicyException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(content);
        } catch (NoSuchAlgorithmException exception) {
            throw new PolicyException("SHA-256 is unavailable", exception);
        }
    }

    private static long safeAdd(long left, long right) throws PolicyException {
        try {
            return Math.addExact(left, right);
        } catch (ArithmeticException exception) {
            throw new PolicyException("policy timestamp overflow", exception);
        }
    }

    private static long safeSubtract(long left, long right) throws PolicyException {
        try {
            return Math.subtractExact(left, right);
        } catch (ArithmeticException exception) {
            throw new PolicyException("policy timestamp overflow", exception);
        }
    }
}
