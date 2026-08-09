package com.ellan.mcace.bungeecord;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;
import java.util.Objects;
import java.util.Set;

/** Persists the root identity used to sign Bungee-issued MCAce policies. */
final class BungeeIdentityStore {
    private static final String PRIVATE_FILE = "server-private-key.pk8";
    private static final String PUBLIC_FILE = "server-public-key.txt";

    private BungeeIdentityStore() {
    }

    static KeyPair loadOrCreate(Path directory) throws IOException, EnvelopeException {
        Objects.requireNonNull(directory, "directory");
        Files.createDirectories(directory);
        Path privatePath = directory.resolve(PRIVATE_FILE);
        Path publicPath = directory.resolve(PUBLIC_FILE);
        boolean hasPrivate = Files.exists(privatePath);
        boolean hasPublic = Files.exists(publicPath);
        if (hasPrivate != hasPublic) {
            throw new IOException("MCAce Bungee identity is incomplete; restore both files or neither");
        }
        if (hasPrivate) {
            try {
                KeyPair loaded = new KeyPair(
                        Ed25519Keys.decodePublic(Base64.getDecoder().decode(
                                Files.readString(publicPath, StandardCharsets.US_ASCII).trim())),
                        Ed25519Keys.decodePrivate(Files.readAllBytes(privatePath)));
                if (!keysMatch(loaded)) {
                    throw new IOException("MCAce Bungee identity key files do not match");
                }
                return loaded;
            } catch (IllegalArgumentException exception) {
                throw new IOException("invalid Base64 MCAce Bungee public key", exception);
            }
        }
        KeyPair generated = Ed25519Keys.generate(new SecureRandom());
        atomicWrite(privatePath, generated.getPrivate().getEncoded());
        restrictPrivateFile(privatePath);
        atomicWrite(publicPath, Base64.getEncoder().encode(generated.getPublic().getEncoded()));
        return generated;
    }

    static String fingerprint(KeyPair identity) {
        try {
            return java.util.HexFormat.ofDelimiter(":").withUpperCase().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(identity.getPublic().getEncoded()));
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static void atomicWrite(Path target, byte[] content) throws IOException {
        Path temporary = Files.createTempFile(target.getParent(), target.getFileName().toString(), ".tmp");
        try {
            Files.write(temporary, content);
            try {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException exception) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void restrictPrivateFile(Path privatePath) throws IOException {
        if (Files.getFileStore(privatePath).supportsFileAttributeView("posix")) {
            Files.setPosixFilePermissions(privatePath, Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
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
