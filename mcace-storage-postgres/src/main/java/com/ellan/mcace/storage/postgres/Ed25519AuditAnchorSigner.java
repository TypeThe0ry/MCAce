package com.ellan.mcace.storage.postgres;

import com.ellan.mcace.core.persistence.SecurityPersistenceException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.HexFormat;
import java.util.Objects;

public final class Ed25519AuditAnchorSigner implements AuditAnchorSigner {
    private static final byte[] DOMAIN =
            "mcace-audit-anchor-signature-v1\0".getBytes(StandardCharsets.US_ASCII);
    private final PrivateKey privateKey;
    private final String keyId;

    public Ed25519AuditAnchorSigner(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(publicKey, "publicKey");
        try {
            keyId = HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded()));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    @Override
    public byte[] sign(byte[] anchorSha256) throws SecurityPersistenceException {
        Objects.requireNonNull(anchorSha256, "anchorSha256");
        if (anchorSha256.length != 32) {
            throw new SecurityPersistenceException("audit anchor hash must contain 32 bytes");
        }
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey);
            signature.update(DOMAIN);
            signature.update(anchorSha256);
            return signature.sign();
        } catch (GeneralSecurityException exception) {
            throw new SecurityPersistenceException("cannot sign audit anchor hash", exception);
        }
    }

    @Override
    public String keyId() {
        return keyId;
    }

    public static boolean verify(byte[] anchorSha256, byte[] signed, PublicKey publicKey)
            throws SecurityPersistenceException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(publicKey);
            signature.update(DOMAIN);
            signature.update(anchorSha256);
            return signature.verify(signed);
        } catch (GeneralSecurityException exception) {
            throw new SecurityPersistenceException("cannot verify audit anchor signature", exception);
        }
    }
}
