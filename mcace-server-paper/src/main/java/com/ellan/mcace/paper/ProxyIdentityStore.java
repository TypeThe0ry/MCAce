package com.ellan.mcace.paper;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;

final class ProxyIdentityStore {
    private ProxyIdentityStore() {
    }

    static PublicKey load(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        Files.createDirectories(path.toAbsolutePath().getParent());
        if (!Files.isRegularFile(path)) {
            throw new IOException("missing pinned proxy public key: " + path);
        }
        String encoded = Files.readString(path, StandardCharsets.US_ASCII).trim();
        if (encoded.isEmpty() || encoded.length() > 4096) {
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
