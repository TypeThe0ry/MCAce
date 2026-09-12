package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.authority.AuthorityFilePreflight;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;
import java.util.Arrays;
import java.util.Objects;

/** Persists the root identity used to sign Bungee-issued MCAce policies. */
final class BungeeIdentityStore {
    private static final String PRIVATE_FILE = "server-private-key.pk8";
    private static final String PUBLIC_FILE = "server-public-key.txt";
    private static final int MAXIMUM_KEY_FILE_BYTES = 4096;

    private BungeeIdentityStore() {
    }

    static KeyPair loadOrCreate(Path directory) throws IOException, EnvelopeException {
        Path root = AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                Objects.requireNonNull(directory, "directory"),
                "MCAce Bungee identity directory");
        Path privatePath = root.resolve(PRIVATE_FILE);
        Path publicPath = root.resolve(PUBLIC_FILE);
        boolean hasPrivate = Files.exists(privatePath, LinkOption.NOFOLLOW_LINKS);
        boolean hasPublic = Files.exists(publicPath, LinkOption.NOFOLLOW_LINKS);
        if (hasPrivate != hasPublic) {
            throw new IOException("MCAce Bungee identity is incomplete; restore both files or neither");
        }
        if (hasPrivate) {
            byte[] privateBytes = AuthorityFilePreflight.readBoundedPrivateRegularFile(
                    root, privatePath, MAXIMUM_KEY_FILE_BYTES,
                    "MCAce Bungee private identity key");
            try {
                byte[] publicFile = AuthorityFilePreflight.readBoundedPrivateRegularFile(
                        root, publicPath, MAXIMUM_KEY_FILE_BYTES,
                        "MCAce Bungee public identity key");
                KeyPair loaded = new KeyPair(
                        Ed25519Keys.decodePublic(Base64.getDecoder().decode(
                                new String(publicFile, StandardCharsets.US_ASCII).strip())),
                        Ed25519Keys.decodePrivate(privateBytes));
                if (!keysMatch(loaded)) {
                    throw new IOException("MCAce Bungee identity key files do not match");
                }
                return loaded;
            } catch (IllegalArgumentException exception) {
                throw new IOException("invalid Base64 MCAce Bungee public key", exception);
            } finally {
                Arrays.fill(privateBytes, (byte) 0);
            }
        }
        KeyPair generated = Ed25519Keys.generate(new SecureRandom());
        byte[] privateBytes = generated.getPrivate().getEncoded();
        boolean privatePublished = false;
        try {
            AuthorityFilePreflight.writePrivateFileAtomically(
                    root, privatePath, privateBytes, "MCAce Bungee private identity key");
            privatePublished = true;
            AuthorityFilePreflight.writePrivateFileAtomically(
                    root, publicPath, Base64.getEncoder().encode(generated.getPublic().getEncoded()),
                    "MCAce Bungee public identity key");
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

    static String fingerprint(KeyPair identity) {
        try {
            return java.util.HexFormat.ofDelimiter(":").withUpperCase().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(identity.getPublic().getEncoded()));
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static boolean keysMatch(KeyPair keyPair) throws IOException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(keyPair.getPrivate());
            signature.update("mcace-bungeecord-key-check-v1".getBytes(StandardCharsets.US_ASCII));
            byte[] signed = signature.sign();
            signature.initVerify(keyPair.getPublic());
            signature.update("mcace-bungeecord-key-check-v1".getBytes(StandardCharsets.US_ASCII));
            return signature.verify(signed);
        } catch (GeneralSecurityException exception) {
            throw new IOException("unable to validate MCAce Bungee identity", exception);
        }
    }
}
