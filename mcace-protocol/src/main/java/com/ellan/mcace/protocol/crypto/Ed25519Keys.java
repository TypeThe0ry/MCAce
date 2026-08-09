package com.ellan.mcace.protocol.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

public final class Ed25519Keys {
    private Ed25519Keys() {
    }

    public static KeyPair generate(SecureRandom secureRandom) throws EnvelopeException {
        Objects.requireNonNull(secureRandom, "secureRandom");
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            generator.initialize(NamedParameterSpec.ED25519, secureRandom);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException exception) {
            throw new EnvelopeException("failed to generate Ed25519 key pair", exception);
        }
    }

    public static PublicKey decodePublic(byte[] encoded) throws EnvelopeException {
        Objects.requireNonNull(encoded, "encoded");
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));
        } catch (GeneralSecurityException exception) {
            throw new EnvelopeException("invalid Ed25519 public key", exception);
        }
    }

    public static PrivateKey decodePrivate(byte[] encoded) throws EnvelopeException {
        Objects.requireNonNull(encoded, "encoded");
        try {
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (GeneralSecurityException exception) {
            throw new EnvelopeException("invalid Ed25519 private key", exception);
        }
    }
}
