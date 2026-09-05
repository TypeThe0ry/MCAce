package com.ellan.mcace.velocity;

import com.ellan.mcace.core.authority.AuthorityFilePreflight;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.policy.PolicyException;
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
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

final class DelegatedPolicyKeyStore {
    private static final String PRIVATE_FILE = "delegated-private-key.pk8";
    private static final String PUBLIC_FILE = "delegated-public-key.x509";
    private static final int MAXIMUM_KEY_FILE_BYTES = 4096;

    private DelegatedPolicyKeyStore() {
    }

    static synchronized Optional<KeyPair> load(Path directory) throws PolicyException {
        Path root = Objects.requireNonNull(directory, "directory").toAbsolutePath().normalize();
        boolean directoryExists = Files.exists(root, LinkOption.NOFOLLOW_LINKS);
        if (!directoryExists) {
            if (Files.notExists(root, LinkOption.NOFOLLOW_LINKS)) {
                return Optional.empty();
            }
            throw new PolicyException("cannot inspect delegated policy key directory");
        }

        try {
            AuthorityFilePreflight.requirePrivateDirectory(
                    root, "MCAce Velocity delegated policy key directory");
            Path privatePath = root.resolve(PRIVATE_FILE);
            Path publicPath = root.resolve(PUBLIC_FILE);
            boolean privateExists = Files.exists(privatePath, LinkOption.NOFOLLOW_LINKS);
            boolean publicExists = Files.exists(publicPath, LinkOption.NOFOLLOW_LINKS);
            if (privateExists != publicExists) {
                throw new PolicyException("delegated policy key store is incomplete");
            }
            if (!privateExists) {
                return Optional.empty();
            }

            byte[] publicBytes = AuthorityFilePreflight.readBoundedPrivateRegularFile(
                    root, publicPath, MAXIMUM_KEY_FILE_BYTES,
                    "MCAce Velocity delegated policy public key");
            byte[] privateBytes = AuthorityFilePreflight.readBoundedPrivateRegularFile(
                    root, privatePath, MAXIMUM_KEY_FILE_BYTES,
                    "MCAce Velocity delegated policy private key");
            try {
                KeyPair pair = new KeyPair(
                        Ed25519Keys.decodePublic(publicBytes),
                        Ed25519Keys.decodePrivate(privateBytes));
                if (!matches(pair)) {
                    throw new PolicyException("delegated policy key pair does not match");
                }
                return Optional.of(pair);
            } finally {
                Arrays.fill(privateBytes, (byte) 0);
            }
        } catch (IOException | EnvelopeException exception) {
            throw new PolicyException("cannot load delegated policy key", exception);
        }
    }

    static synchronized KeyPair rotate(Path directory, SecureRandom random)
            throws PolicyException {
        Path root;
        try {
            root = AuthorityFilePreflight.createPrivateDirectoriesWithoutLinks(
                    Objects.requireNonNull(directory, "directory"),
                    "MCAce Velocity delegated policy key directory");
        } catch (IOException exception) {
            throw new PolicyException("cannot prepare delegated policy key directory", exception);
        }

        Optional<KeyPair> previous = load(root);
        byte[] previousPublic = previous.map(pair -> pair.getPublic().getEncoded()).orElse(null);
        byte[] previousPrivate = previous.map(pair -> pair.getPrivate().getEncoded()).orElse(null);
        byte[] privateBytes = null;
        boolean publicPublished = false;
        try {
            KeyPair generated = Ed25519Keys.generate(Objects.requireNonNull(random, "random"));
            byte[] publicBytes = Objects.requireNonNull(
                    generated.getPublic().getEncoded(), "encoded delegated public key");
            privateBytes = Objects.requireNonNull(
                    generated.getPrivate().getEncoded(), "encoded delegated private key");
            publish(root, root.resolve(PUBLIC_FILE), publicBytes,
                    "MCAce Velocity delegated policy public key");
            publicPublished = true;
            publish(root, root.resolve(PRIVATE_FILE), privateBytes,
                    "MCAce Velocity delegated policy private key");

            KeyPair persisted = load(root).orElseThrow(
                    () -> new PolicyException("delegated policy key disappeared after rotation"));
            if (!MessageDigest.isEqual(
                    generated.getPublic().getEncoded(), persisted.getPublic().getEncoded())) {
                throw new PolicyException("delegated policy key changed during rotation");
            }
            return generated;
        } catch (IOException | EnvelopeException exception) {
            PolicyException failure = new PolicyException(
                    "cannot persist delegated policy key", exception);
            rollbackPair(
                    root, previousPublic, previousPrivate, publicPublished, failure);
            throw failure;
        } catch (PolicyException failure) {
            rollbackPair(
                    root, previousPublic, previousPrivate, publicPublished, failure);
            throw failure;
        } finally {
            if (privateBytes != null) {
                Arrays.fill(privateBytes, (byte) 0);
            }
            if (previousPrivate != null) {
                Arrays.fill(previousPrivate, (byte) 0);
            }
        }
    }

    private static void publish(Path root, Path target, byte[] content, String description)
            throws IOException {
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            AuthorityFilePreflight.replacePrivateFileAtomically(
                    root, target, content, description);
        } else {
            AuthorityFilePreflight.writePrivateFileAtomically(
                    root, target, content, description);
        }
    }

    private static void rollbackPair(
            Path root,
            byte[] previousPublic,
            byte[] previousPrivate,
            boolean publicPublished,
            PolicyException failure) {
        if (!publicPublished) {
            return;
        }
        Path privatePath = root.resolve(PRIVATE_FILE);
        Path publicPath = root.resolve(PUBLIC_FILE);
        if (previousPrivate == null) {
            deletePrivateFileIfPresent(root, privatePath,
                    "incomplete MCAce Velocity delegated policy private key", failure);
        } else {
            try {
                publish(root, privatePath, previousPrivate,
                        "rollback MCAce Velocity delegated policy private key");
            } catch (IOException rollbackFailure) {
                failure.addSuppressed(rollbackFailure);
            }
        }
        if (previousPublic == null) {
            deletePrivateFileIfPresent(root, publicPath,
                    "incomplete MCAce Velocity delegated policy public key", failure);
        } else {
            try {
                publish(root, publicPath, previousPublic,
                        "rollback MCAce Velocity delegated policy public key");
            } catch (IOException rollbackFailure) {
                failure.addSuppressed(rollbackFailure);
            }
        }
    }

    private static void deletePrivateFileIfPresent(
            Path root, Path path, String description, PolicyException failure) {
        try {
            if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                AuthorityFilePreflight.requirePrivateRegularFile(root, path, description);
                Files.delete(path);
            }
        } catch (IOException rollbackFailure) {
            failure.addSuppressed(rollbackFailure);
        }
    }

    private static boolean matches(KeyPair pair) throws PolicyException {
        try {
            byte[] challenge = "mcace-delegated-policy-key-check-v1"
                    .getBytes(StandardCharsets.US_ASCII);
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
}
