package com.ellan.mcace.velocity;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.policy.PolicyException;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Optional;
import java.util.Set;

final class DelegatedPolicyKeyStore {
    private static final String PRIVATE_FILE = "delegated-private-key.pk8";
    private static final String PUBLIC_FILE = "delegated-public-key.x509";

    private DelegatedPolicyKeyStore() {
    }

    static Optional<KeyPair> load(Path directory) throws PolicyException {
        Path privatePath = directory.resolve(PRIVATE_FILE);
        Path publicPath = directory.resolve(PUBLIC_FILE);
        boolean privateExists = Files.exists(privatePath);
        boolean publicExists = Files.exists(publicPath);
        if (privateExists != publicExists) {
            throw new PolicyException("delegated policy key store is incomplete");
        }
        if (!privateExists) {
            return Optional.empty();
        }
        try {
            KeyPair pair = new KeyPair(
                    Ed25519Keys.decodePublic(Files.readAllBytes(publicPath)),
                    Ed25519Keys.decodePrivate(Files.readAllBytes(privatePath)));
            if (!matches(pair)) {
                throw new PolicyException("delegated policy key pair does not match");
            }
            return Optional.of(pair);
        } catch (IOException | EnvelopeException exception) {
            throw new PolicyException("cannot load delegated policy key", exception);
        }
    }

    static KeyPair rotate(Path directory, SecureRandom random) throws PolicyException {
        try {
            Files.createDirectories(directory);
            KeyPair pair = Ed25519Keys.generate(random);
            atomicReplace(directory.resolve(PRIVATE_FILE), pair.getPrivate().getEncoded());
            restrictPrivateFile(directory.resolve(PRIVATE_FILE));
            atomicReplace(directory.resolve(PUBLIC_FILE), pair.getPublic().getEncoded());
            return pair;
        } catch (IOException | EnvelopeException exception) {
            throw new PolicyException("cannot persist delegated policy key", exception);
        }
    }

    private static boolean matches(KeyPair pair) throws PolicyException {
        try {
            byte[] challenge = "mcace-delegated-policy-key-check-v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(pair.getPrivate());
            signature.update(challenge);
            byte[] signed = signature.sign();
            signature.initVerify(pair.getPublic());
            signature.update(challenge);
            return signature.verify(signed);
        } catch (GeneralSecurityException exception) {
            throw new PolicyException("cannot validate delegated policy key", exception);
        }
    }

    private static void atomicReplace(Path target, byte[] content) throws IOException {
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
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE));
        }
    }
}
