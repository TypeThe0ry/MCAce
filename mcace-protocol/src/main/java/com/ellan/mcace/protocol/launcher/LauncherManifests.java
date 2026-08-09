package com.ellan.mcace.protocol.launcher;

import com.ellan.mcace.protocol.generated.LauncherFile;
import com.ellan.mcace.protocol.generated.LauncherManifest;
import com.ellan.mcace.protocol.generated.LauncherSigningKey;
import com.ellan.mcace.protocol.generated.LauncherTrustStatement;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.SignedLauncherManifest;
import com.ellan.mcace.protocol.generated.SignedLauncherTrustStatement;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.net.URI;
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
import java.util.Objects;
import java.util.Set;

public final class LauncherManifests {
    private static final byte[] MANIFEST_DOMAIN =
            "mcace-launcher-manifest-v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] TRUST_DOMAIN =
            "mcace-launcher-trust-v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final Duration MAX_MANIFEST_LIFETIME = Duration.ofDays(7);
    private static final Duration MAX_TRUST_LIFETIME = Duration.ofDays(45);
    private static final int MAX_FILES = 8192;
    private static final int MAX_KEYS = 16;
    private static final int MAX_REVOKED = 512;

    private LauncherManifests() { }

    public static SignedLauncherManifest sign(
            LauncherManifest manifest, PrivateKey privateKey, PublicKey publicKey)
            throws LauncherException {
        return signInternal(manifest, privateKey, publicKey, null);
    }

    public static SignedLauncherManifest signDelegated(
            LauncherManifest manifest,
            PrivateKey privateKey,
            PublicKey publicKey,
            SignedLauncherTrustStatement trust) throws LauncherException {
        return signInternal(manifest, privateKey, publicKey, Objects.requireNonNull(trust, "trust"));
    }

    private static SignedLauncherManifest signInternal(
            LauncherManifest manifest,
            PrivateKey privateKey,
            PublicKey publicKey,
            SignedLauncherTrustStatement trust) throws LauncherException {
        Objects.requireNonNull(manifest, "manifest");
        Objects.requireNonNull(privateKey, "privateKey");
        byte[] keyId = keyId(Objects.requireNonNull(publicKey, "publicKey"));
        validateManifest(manifest);
        if (!MessageDigest.isEqual(keyId, manifest.getSignerKeyIdSha256().toByteArray())) {
            throw new LauncherException("launcher manifest signer id does not match signing key");
        }
        byte[] body = manifest.toByteArray();
        SignedLauncherManifest.Builder signed = SignedLauncherManifest.newBuilder()
                .setManifest(ByteString.copyFrom(body))
                .setSignerKeyIdSha256(ByteString.copyFrom(keyId))
                .setSignature(ByteString.copyFrom(sign(domainBytes(MANIFEST_DOMAIN, body), privateKey)));
        if (trust != null) signed.setTrustStatement(trust);
        return signed.build();
    }

    public static SignedLauncherTrustStatement signTrustStatement(
            LauncherTrustStatement statement, PrivateKey privateKey, PublicKey publicKey)
            throws LauncherException {
        Objects.requireNonNull(statement, "statement");
        byte[] rootId = keyId(Objects.requireNonNull(publicKey, "publicKey"));
        validateTrust(statement, rootId);
        if (!MessageDigest.isEqual(rootId, statement.getRootKeyIdSha256().toByteArray())) {
            throw new LauncherException("launcher trust root id does not match signing key");
        }
        byte[] body = statement.toByteArray();
        return SignedLauncherTrustStatement.newBuilder()
                .setStatement(ByteString.copyFrom(body))
                .setRootKeyIdSha256(ByteString.copyFrom(rootId))
                .setSignature(ByteString.copyFrom(sign(domainBytes(TRUST_DOMAIN, body), privateKey)))
                .build();
    }

    public static LauncherVerification verify(
            SignedLauncherManifest signed, PublicKey rootKey, Clock clock, Duration skew)
            throws LauncherException {
        LauncherVerification verification = verifySignatureAndStructure(signed, rootKey);
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(skew, "skew");
        if (skew.isNegative() || skew.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new LauncherException("launcher clock skew is invalid");
        }
        long now = clock.millis();
        checkCurrent(verification.manifest().getIssuedAtEpochMs(),
                verification.manifest().getExpiresAtEpochMs(), now, skew, "manifest");
        if (verification.delegated()) {
            LauncherTrustStatement trust = parseTrust(signed.getTrustStatement(), rootKey);
            checkCurrent(trust.getIssuedAtEpochMs(), trust.getExpiresAtEpochMs(), now, skew, "trust statement");
        }
        return verification;
    }

    public static LauncherVerification verifySignatureAndStructure(
            SignedLauncherManifest signed, PublicKey rootKey) throws LauncherException {
        Objects.requireNonNull(signed, "signed");
        Objects.requireNonNull(rootKey, "rootKey");
        if (signed.getManifest().isEmpty() || signed.getSignature().size() != 64
                || signed.getSignerKeyIdSha256().size() != 32) {
            throw new LauncherException("signed launcher manifest is incomplete");
        }
        byte[] rootId = keyId(rootKey);
        byte[] signerId = signed.getSignerKeyIdSha256().toByteArray();
        boolean delegated = !MessageDigest.isEqual(rootId, signerId);
        PublicKey signingKey = rootKey;
        long trustSequence = 0;
        LauncherTrustStatement trust = null;
        LauncherSigningKey authorized = null;
        if (delegated) {
            if (!signed.hasTrustStatement()) {
                throw new LauncherException("delegated launcher manifest has no root trust statement");
            }
            trust = parseTrust(signed.getTrustStatement(), rootKey);
            trustSequence = trust.getSequence();
            for (ByteString revoked : trust.getRevokedKeyIdsSha256List()) {
                if (MessageDigest.isEqual(signerId, revoked.toByteArray())) {
                    throw new LauncherException("launcher release signer is revoked");
                }
            }
            for (LauncherSigningKey candidate : trust.getReleaseSigningKeysList()) {
                if (MessageDigest.isEqual(signerId, candidate.getKeyIdSha256().toByteArray())) {
                    authorized = candidate;
                    break;
                }
            }
            if (authorized == null) throw new LauncherException("launcher release signer is unauthorized");
            signingKey = decodePublic(authorized.getPublicKeyX509().toByteArray());
        } else if (signed.hasTrustStatement()) {
            throw new LauncherException("root-signed launcher manifest must not embed delegated trust");
        }
        if (!verifySignature(domainBytes(MANIFEST_DOMAIN, signed.getManifest().toByteArray()),
                signed.getSignature().toByteArray(), signingKey)) {
            throw new LauncherException("launcher manifest signature is invalid");
        }
        LauncherManifest manifest;
        try {
            manifest = LauncherManifest.parseFrom(signed.getManifest());
        } catch (InvalidProtocolBufferException exception) {
            throw new LauncherException("launcher manifest protobuf is malformed", exception);
        }
        validateManifest(manifest);
        if (!MessageDigest.isEqual(signerId, manifest.getSignerKeyIdSha256().toByteArray())) {
            throw new LauncherException("launcher manifest signer id differs from envelope");
        }
        if (delegated && (!trust.getProductId().equals(manifest.getProductId())
                || manifest.getIssuedAtEpochMs() < authorized.getNotBeforeEpochMs()
                || manifest.getExpiresAtEpochMs() > authorized.getNotAfterEpochMs())) {
            throw new LauncherException("launcher manifest exceeds release-key authorization");
        }
        return new LauncherVerification(manifest, trustSequence, delegated, signerId);
    }

    public static byte[] keyId(PublicKey key) throws LauncherException {
        return sha256(Objects.requireNonNull(key, "key").getEncoded());
    }

    public static byte[] manifestDigest(SignedLauncherManifest manifest) throws LauncherException {
        if (manifest.getManifest().isEmpty()) throw new LauncherException("launcher manifest is empty");
        return sha256(manifest.getManifest().toByteArray());
    }

    private static LauncherTrustStatement parseTrust(
            SignedLauncherTrustStatement signed, PublicKey rootKey) throws LauncherException {
        byte[] rootId = keyId(rootKey);
        if (signed.getStatement().isEmpty() || signed.getSignature().size() != 64
                || !MessageDigest.isEqual(rootId, signed.getRootKeyIdSha256().toByteArray())
                || !verifySignature(domainBytes(TRUST_DOMAIN, signed.getStatement().toByteArray()),
                        signed.getSignature().toByteArray(), rootKey)) {
            throw new LauncherException("launcher trust statement signature is invalid");
        }
        LauncherTrustStatement statement;
        try {
            statement = LauncherTrustStatement.parseFrom(signed.getStatement());
        } catch (InvalidProtocolBufferException exception) {
            throw new LauncherException("launcher trust statement protobuf is malformed", exception);
        }
        validateTrust(statement, rootId);
        return statement;
    }

    private static void validateManifest(LauncherManifest value) throws LauncherException {
        if (value.getSchemaVersion() != 1 || value.getReleaseSequence() <= 0
                || !identifier(value.getProductId()) || !identifier(value.getReleaseId())
                || !identifier(value.getBuildId()) || value.getMinecraftVersion().isBlank()
                || !value.getMinimumLauncherVersion().matches("[0-9]{1,6}\\.[0-9]{1,6}\\.[0-9]{1,6}")
                || value.getLoader() == LoaderType.LOADER_UNSPECIFIED
                || value.getLoader() == LoaderType.UNRECOGNIZED
                || value.getSignerKeyIdSha256().size() != 32
                || value.getFilesCount() == 0 || value.getFilesCount() > MAX_FILES) {
            throw new LauncherException("launcher manifest identity or compatibility fields are invalid");
        }
        requireLifetime(value.getIssuedAtEpochMs(), value.getExpiresAtEpochMs(), MAX_MANIFEST_LIFETIME,
                "launcher manifest");
        Set<String> paths = new HashSet<>();
        String previous = "";
        for (LauncherFile file : value.getFilesList()) {
            String path = file.getRelativePath();
            validatePath(path);
            URI uri;
            try { uri = URI.create(file.getDownloadUri()); }
            catch (IllegalArgumentException exception) { throw new LauncherException("launcher file URI is invalid", exception); }
            if (file.getFileSize() > 4L * 1024 * 1024 * 1024
                    || file.getSha256().size() != 32 || !paths.add(path)
                    || path.compareTo(previous) <= 0 || !"https".equalsIgnoreCase(uri.getScheme())
                    || uri.getHost() == null || uri.getUserInfo() != null
                    || uri.getQuery() != null || uri.getFragment() != null) {
                throw new LauncherException("launcher file metadata is invalid or non-canonical");
            }
            previous = path;
        }
    }

    private static void validateTrust(LauncherTrustStatement value, byte[] rootId)
            throws LauncherException {
        if (value.getSequence() <= 0 || !identifier(value.getProductId())
                || !MessageDigest.isEqual(rootId, value.getRootKeyIdSha256().toByteArray())
                || value.getReleaseSigningKeysCount() == 0
                || value.getReleaseSigningKeysCount() > MAX_KEYS
                || value.getRevokedKeyIdsSha256Count() > MAX_REVOKED) {
            throw new LauncherException("launcher trust identity or key count is invalid");
        }
        requireLifetime(value.getIssuedAtEpochMs(), value.getExpiresAtEpochMs(), MAX_TRUST_LIFETIME,
                "launcher trust statement");
        Set<ByteString> authorized = new HashSet<>();
        for (LauncherSigningKey key : value.getReleaseSigningKeysList()) {
            if (key.getKeyIdSha256().size() != 32 || key.getPublicKeyX509().isEmpty()
                    || key.getNotBeforeEpochMs() < value.getIssuedAtEpochMs()
                    || key.getNotAfterEpochMs() > value.getExpiresAtEpochMs()
                    || key.getNotAfterEpochMs() <= key.getNotBeforeEpochMs()
                    || !authorized.add(key.getKeyIdSha256())) {
                throw new LauncherException("launcher release-key authorization is invalid");
            }
            PublicKey decoded = decodePublic(key.getPublicKeyX509().toByteArray());
            if (!MessageDigest.isEqual(keyId(decoded), key.getKeyIdSha256().toByteArray())) {
                throw new LauncherException("launcher release key id is invalid");
            }
        }
        Set<ByteString> revoked = new HashSet<>();
        for (ByteString key : value.getRevokedKeyIdsSha256List()) {
            if (key.size() != 32 || MessageDigest.isEqual(rootId, key.toByteArray())
                    || authorized.contains(key) || !revoked.add(key)) {
                throw new LauncherException("launcher revoked key set conflicts with authorization");
            }
        }
    }

    private static boolean identifier(String value) {
        return value != null && value.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
    }

    private static void validatePath(String value) throws LauncherException {
        if (value.isBlank() || value.length() > 240 || value.startsWith("/") || value.contains("\\")
                || value.contains(":") || value.equals("..") || value.startsWith("../")
                || value.endsWith("/..") || value.contains("/../") || value.contains("//")) {
            throw new LauncherException("launcher file path is unsafe");
        }
    }

    private static void requireLifetime(long issued, long expires, Duration maximum, String label)
            throws LauncherException {
        long lifetime;
        try { lifetime = Math.subtractExact(expires, issued); }
        catch (ArithmeticException exception) { throw new LauncherException(label + " timestamp overflow", exception); }
        if (lifetime <= 0 || lifetime > maximum.toMillis()) {
            throw new LauncherException(label + " lifetime is invalid");
        }
    }

    private static void checkCurrent(long issued, long expires, long now, Duration skew, String label)
            throws LauncherException {
        if (issued > now + skew.toMillis() || expires <= now - skew.toMillis()) {
            throw new LauncherException(label + " is not current");
        }
    }

    private static byte[] domainBytes(byte[] domain, byte[] body) {
        return ByteBuffer.allocate(domain.length + Integer.BYTES + body.length)
                .put(domain).putInt(body.length).put(body).array();
    }

    private static byte[] sign(byte[] content, PrivateKey key) throws LauncherException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(key); signature.update(content); return signature.sign();
        } catch (GeneralSecurityException exception) {
            throw new LauncherException("cannot sign launcher document", exception);
        }
    }

    private static boolean verifySignature(byte[] content, byte[] signed, PublicKey key)
            throws LauncherException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(key); signature.update(content); return signature.verify(signed);
        } catch (GeneralSecurityException exception) {
            throw new LauncherException("cannot verify launcher document", exception);
        }
    }

    private static PublicKey decodePublic(byte[] encoded) throws LauncherException {
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));
        } catch (GeneralSecurityException exception) {
            throw new LauncherException("launcher release public key is invalid", exception);
        }
    }

    private static byte[] sha256(byte[] content) throws LauncherException {
        try { return MessageDigest.getInstance("SHA-256").digest(content); }
        catch (NoSuchAlgorithmException exception) { throw new LauncherException("SHA-256 is unavailable", exception); }
    }
}
