package com.ellan.mcace.velocity;

import com.ellan.mcace.core.authority.AuthorityFilePreflight;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Arrays;

final class ServerIdentityStore {
    private static final String PRIVATE_FILE = "server-private-key.pk8";
    private static final String PUBLIC_FILE = "server-public-key.txt";
    private static final int MAXIMUM_KEY_FILE_BYTES = 4096;

    private ServerIdentityStore() {
    }

    static KeyPair loadOrCreate(Path directory) throws IOException, EnvelopeException {
        Path root = AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                directory, "MCAce Velocity identity directory");
        Path privatePath = root.resolve(PRIVATE_FILE);
        Path publicPath = root.resolve(PUBLIC_FILE);
        boolean privateExists = Files.exists(privatePath, LinkOption.NOFOLLOW_LINKS);
        boolean publicExists = Files.exists(publicPath, LinkOption.NOFOLLOW_LINKS);
        if (privateExists != publicExists) {
            throw new IOException("MCAce server identity is incomplete; restore both key files or neither");
        }
        if (privateExists) {
            byte[] privateBytes = AuthorityFilePreflight.readBoundedPrivateRegularFile(
                    root, privatePath, MAXIMUM_KEY_FILE_BYTES,
                    "MCAce Velocity private identity key");
            try {
                byte[] publicFile = AuthorityFilePreflight.readBoundedPrivateRegularFile(
                        root, publicPath, MAXIMUM_KEY_FILE_BYTES,
                        "MCAce Velocity public identity key");
                byte[] publicBytes;
                try {
                    publicBytes = Base64.getDecoder().decode(
                            new String(publicFile, StandardCharsets.US_ASCII).strip());
                } catch (IllegalArgumentException exception) {
                    throw new IOException("invalid Base64 MCAce public key", exception);
                }
                KeyPair loaded = new KeyPair(
                        Ed25519Keys.decodePublic(publicBytes),
                        Ed25519Keys.decodePrivate(privateBytes));
                if (!keysMatch(loaded)) {
                    throw new IOException("MCAce public and private server identity files do not match");
                }
                return loaded;
            } finally {
                Arrays.fill(privateBytes, (byte) 0);
            }
        }
        KeyPair generated = Ed25519Keys.generate(new SecureRandom());
        byte[] privateBytes = generated.getPrivate().getEncoded();
        boolean privatePublished = false;
        try {
            AuthorityFilePreflight.writePrivateFileAtomically(
                    root, privatePath, privateBytes, "MCAce Velocity private identity key");
            privatePublished = true;
            AuthorityFilePreflight.writePrivateFileAtomically(
                    root, publicPath, Base64.getEncoder().encode(generated.getPublic().getEncoded()),
                    "MCAce Velocity public identity key");
            return generated;
        } catch (IOException exception) {
            if (privatePublished) {
                Files.deleteIfExists(privatePath);
            }
            throw exception;
        } finally {
            Arrays.fill(privateBytes, (byte) 0);
        }
    }

    static String fingerprint(KeyPair keyPair) {
        try {
            return HexFormat.ofDelimiter(":").withUpperCase()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(keyPair.getPublic().getEncoded()));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static boolean keysMatch(KeyPair keyPair) throws IOException {
        try {
            byte[] challenge = "mcace-server-key-check-v1".getBytes(StandardCharsets.US_ASCII);
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(keyPair.getPrivate());
            signature.update(challenge);
            byte[] signed = signature.sign();
            signature.initVerify(keyPair.getPublic());
            signature.update(challenge);
            return signature.verify(signed);
        } catch (GeneralSecurityException exception) {
            throw new IOException("unable to validate MCAce server identity", exception);
        }
    }
}
