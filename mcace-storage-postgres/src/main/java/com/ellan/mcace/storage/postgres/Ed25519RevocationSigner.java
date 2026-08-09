package com.ellan.mcace.storage.postgres;

import com.ellan.mcace.core.persistence.RevocationSignatureCodec;
import com.ellan.mcace.core.persistence.SecurityPersistenceException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.HexFormat;
import java.util.Objects;

public final class Ed25519RevocationSigner implements RevocationSigner {
    private final PrivateKey privateKey;
    private final String keyId;

    public Ed25519RevocationSigner(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
        Objects.requireNonNull(publicKey, "publicKey");
        try {
            keyId = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded()));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    @Override
    public byte[] sign(byte[] payloadSha256) throws SecurityPersistenceException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey);
            signature.update(RevocationSignatureCodec.signingMessage(payloadSha256));
            return signature.sign();
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new SecurityPersistenceException("cannot sign revocation", exception);
        }
    }

    @Override
    public String keyId() {
        return keyId;
    }
}
