package com.ellan.mcace.paper;

import com.ellan.mcace.core.authority.AuthorityFilePreflight;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;

final class ProxyIdentityStore {
    private static final int MAXIMUM_PUBLIC_KEY_FILE_BYTES = 4096;

    private ProxyIdentityStore() {
    }

    static PublicKey load(Path path) throws IOException {
        Path normalized = Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
        Path root = Objects.requireNonNull(normalized.getParent(), "proxy pin parent");
        byte[] content = AuthorityFilePreflight.readBoundedIntegrityProtectedRegularFile(
                root, normalized, MAXIMUM_PUBLIC_KEY_FILE_BYTES,
                "pinned proxy public key");
        String encoded = new String(content, StandardCharsets.US_ASCII).strip();
        if (encoded.isEmpty()) {
            throw new IOException("invalid pinned proxy public-key file");
        }
        try {
            return Ed25519Keys.decodePublic(Base64.getDecoder().decode(encoded));
        } catch (IllegalArgumentException | EnvelopeException exception) {
            throw new IOException("invalid pinned proxy Ed25519 public key", exception);
        }
    }

    static String fingerprint(PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "publicKey");
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded()));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
