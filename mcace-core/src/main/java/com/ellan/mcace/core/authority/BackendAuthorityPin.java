package com.ellan.mcace.core.authority;

import com.ellan.mcace.protocol.ProtocolConstants;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Operator-supplied exact backend identity, key and allowed authority profiles. */
public record BackendAuthorityPin(
        String registeredBackend,
        String backendInstanceId,
        String keyIdSha256,
        PublicKey publicKey,
        Map<String, BackendAuthorityProfile> authorityProfiles) {
    public BackendAuthorityPin {
        registeredBackend = bounded(registeredBackend, "registeredBackend");
        backendInstanceId = bounded(backendInstanceId, "backendInstanceId");
        keyIdSha256 = sha256(keyIdSha256, "keyIdSha256");
        Objects.requireNonNull(publicKey, "publicKey");
        if (!"EdDSA".equalsIgnoreCase(publicKey.getAlgorithm())
                && !"Ed25519".equalsIgnoreCase(publicKey.getAlgorithm())) {
            throw new IllegalArgumentException("backend authority key must be Ed25519");
        }
        try {
            publicKey = KeyFactory.getInstance("Ed25519").generatePublic(
                    new X509EncodedKeySpec(publicKey.getEncoded()));
        } catch (GeneralSecurityException | RuntimeException exception) {
            throw new IllegalArgumentException("backend authority key is not canonical Ed25519", exception);
        }
        if (!java.security.MessageDigest.isEqual(
                java.util.HexFormat.of().parseHex(keyIdSha256),
                java.util.HexFormat.of().parseHex(AuthorityProtocolSupport.publicKeyId(publicKey)))) {
            throw new IllegalArgumentException("backend authority key ID does not match the public key");
        }
        authorityProfiles = copyProfiles(authorityProfiles);
    }

    /** Canonical lowercase SHA-256 fingerprint used by the wire key-id field. */
    public static String keyIdFor(PublicKey publicKey) {
        return AuthorityProtocolSupport.publicKeyId(Objects.requireNonNull(publicKey, "publicKey"));
    }

    public Set<String> allowedProfileSha256() {
        return authorityProfiles.keySet();
    }

    public Optional<BackendAuthorityProfile> authorityProfile(String sha256) {
        return Optional.ofNullable(authorityProfiles.get(sha256));
    }

    private static Map<String, BackendAuthorityProfile> copyProfiles(
            Map<String, BackendAuthorityProfile> values) {
        Objects.requireNonNull(values, "authorityProfiles");
        if (values.isEmpty() || values.size() > ProtocolConstants.MAX_BACKEND_AUTHORITY_PROVIDERS) {
            throw new IllegalArgumentException("authorityProfiles is empty or outside bounds");
        }
        java.util.LinkedHashMap<String, BackendAuthorityProfile> copy = new java.util.LinkedHashMap<>();
        values.forEach((digest, profile) -> {
            String canonical = sha256(digest, "authorityProfileSha256");
            Objects.requireNonNull(profile, "authorityProfile");
            if (!canonical.equals(profile.sha256())) {
                throw new IllegalArgumentException("authority profile digest does not match its content");
            }
            copy.put(canonical, profile);
        });
        return Map.copyOf(copy);
    }

    static String bounded(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isEmpty() || value.length() > ProtocolConstants.MAX_BACKEND_AUTHORITY_TEXT_CHARS
                || value.chars().anyMatch(codeUnit -> codeUnit < 0x21 || codeUnit > 0x7e)) {
            throw new IllegalArgumentException(field + " is outside the bounded authority contract");
        }
        return value;
    }

    static String sha256(String value, String field) {
        Objects.requireNonNull(value, field);
        if (!value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256");
        }
        return value;
    }
}
