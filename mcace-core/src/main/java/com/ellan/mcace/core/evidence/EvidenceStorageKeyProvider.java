package com.ellan.mcace.core.evidence;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.channels.FileChannel;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.spec.SecretKeySpec;

/** Dedicated AES-256 key file helper; it has no API accepting an Ed25519 identity key. */
public final class EvidenceStorageKeyProvider {
    private static final int KEY_BYTES = 32;
    private EvidenceStorageKeyProvider() { }

    public static SecretKeySpec loadOrCreate(Path keyPath, SecureRandom random) throws IOException {
        Objects.requireNonNull(keyPath, "keyPath");
        Objects.requireNonNull(random, "random");
        Path path = keyPath.toAbsolutePath().normalize();
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(path)) throw new IOException("evidence key path is a symlink");
            byte[] key = readExactly(path, KEY_BYTES);
            try { return new SecretKeySpec(key, "AES"); }
            finally { Arrays.fill(key, (byte) 0); }
        }
        Path parent = path.getParent();
        if (parent == null) throw new IOException("evidence key path has no parent");
        Files.createDirectories(parent);
        if (Files.isSymbolicLink(parent)) throw new IOException("evidence key directory is a symlink");
        byte[] key = new byte[KEY_BYTES];
        random.nextBytes(key);
        try {
            try (FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(key);
                while (buffer.hasRemaining()) channel.write(buffer);
                channel.force(true);
            }
        } catch (java.nio.file.FileAlreadyExistsException race) {
            return loadOrCreate(path, random);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
        try {
            Files.setPosixFilePermissions(path, java.util.Set.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException ignored) {
            // Windows and other non-POSIX providers retain provider ACL semantics.
        }
        byte[] stored = readExactly(path, KEY_BYTES);
        try { return new SecretKeySpec(stored, "AES"); }
        finally { Arrays.fill(stored, (byte) 0); }
    }

    private static byte[] readExactly(Path path, int expected) throws IOException {
        long size = Files.size(path);
        if (size != expected) throw new IOException("evidence key must be exactly 32 bytes");
        byte[] key = new byte[expected];
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            ByteBuffer buffer = ByteBuffer.wrap(key);
            while (buffer.hasRemaining()) {
                int read = channel.read(buffer);
                if (read < 0) throw new IOException("truncated evidence key");
            }
        }
        if (Files.size(path) != expected) {
            Arrays.fill(key, (byte) 0);
            throw new IOException("evidence key changed during read");
        }
        return key;
    }
}
