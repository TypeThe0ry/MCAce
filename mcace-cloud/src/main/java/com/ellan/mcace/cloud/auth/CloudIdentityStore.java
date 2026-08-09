package com.ellan.mcace.cloud.auth;

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
import java.util.HexFormat;
import java.util.Set;

public final class CloudIdentityStore {
    private static final String PRIVATE_FILE = "cloud-private-key.pk8";
    private static final String PUBLIC_FILE = "cloud-public-key.txt";

    private CloudIdentityStore() { }

    public static KeyPair loadOrCreate(Path directory) throws IOException, EnvelopeException {
        Files.createDirectories(directory);
        Path privatePath = directory.resolve(PRIVATE_FILE);
        Path publicPath = directory.resolve(PUBLIC_FILE);
        boolean privateExists = Files.exists(privatePath);
        boolean publicExists = Files.exists(publicPath);
        if (privateExists != publicExists) {
            throw new IOException("MCAce cloud identity is incomplete; restore both key files or neither");
        }
        if (privateExists) {
            byte[] publicBytes;
            try {
                publicBytes = Base64.getDecoder().decode(
                        Files.readString(publicPath, StandardCharsets.US_ASCII).trim());
            } catch (IllegalArgumentException exception) {
                throw new IOException("invalid Base64 cloud public key", exception);
            }
            KeyPair loaded = new KeyPair(
                    Ed25519Keys.decodePublic(publicBytes),
                    Ed25519Keys.decodePrivate(Files.readAllBytes(privatePath)));
            if (!keysMatch(loaded)) throw new IOException("cloud identity key files do not match");
            return loaded;
        }
        KeyPair generated = Ed25519Keys.generate(new SecureRandom());
        atomicWrite(privatePath, generated.getPrivate().getEncoded());
        restrictPrivateFile(privatePath);
        atomicWrite(publicPath, Base64.getEncoder().encode(generated.getPublic().getEncoded()));
        return generated;
    }

    public static String keyId(KeyPair identity) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(identity.getPublic().getEncoded()));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static boolean keysMatch(KeyPair keyPair) throws IOException {
        try {
            byte[] challenge = "mcace-cloud-key-check-v1".getBytes(StandardCharsets.US_ASCII);
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(keyPair.getPrivate());
            signature.update(challenge);
            byte[] signed = signature.sign();
            signature.initVerify(keyPair.getPublic());
            signature.update(challenge);
            return signature.verify(signed);
        } catch (GeneralSecurityException exception) {
            throw new IOException("unable to validate cloud identity", exception);
        }
    }

    private static void atomicWrite(Path target, byte[] content) throws IOException {
        Path temporary = Files.createTempFile(target.getParent(), target.getFileName().toString(), ".tmp");
        try {
            Files.write(temporary, content);
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException exception) {
                Files.move(temporary, target);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void restrictPrivateFile(Path privatePath) throws IOException {
        if (Files.getFileStore(privatePath).supportsFileAttributeView("posix")) {
            Files.setPosixFilePermissions(privatePath, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));
        }
    }
}
