package com.ellan.mcace.storage.postgres;

import com.ellan.mcace.core.persistence.SecurityPersistenceException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.HexFormat;
import java.util.Objects;

public final class Ed25519EvidenceChainSigner implements EvidenceChainSigner {
    private static final byte[] DOMAIN = "mcace-evidence-signature-v1\0".getBytes(StandardCharsets.US_ASCII);
    private final PrivateKey privateKey;
    private final String keyId;

    public Ed25519EvidenceChainSigner(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(publicKey, "publicKey");
        try {
            this.keyId = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded()));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    @Override
    public byte[] sign(byte[] chainSha256) throws SecurityPersistenceException {
        Objects.requireNonNull(chainSha256, "chainSha256");
        if (chainSha256.length != 32) {
            throw new SecurityPersistenceException("evidence chain hash must contain 32 bytes");
        }
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey);
            signature.update(DOMAIN);
            signature.update(chainSha256);
            return signature.sign();
        } catch (GeneralSecurityException exception) {
            throw new SecurityPersistenceException("cannot sign evidence chain hash", exception);
        }
    }

    @Override
    public String keyId() {
        return keyId;
    }

    public static boolean verify(byte[] chainSha256, byte[] signed, PublicKey publicKey)
            throws SecurityPersistenceException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(publicKey);
            signature.update(DOMAIN);
            signature.update(chainSha256);
            return signature.verify(signed);
        } catch (GeneralSecurityException exception) {
            throw new SecurityPersistenceException("cannot verify evidence chain signature", exception);
        }
    }
}
