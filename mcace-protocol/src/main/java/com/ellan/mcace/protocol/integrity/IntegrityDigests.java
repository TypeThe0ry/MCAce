package com.ellan.mcace.protocol.integrity;

import com.ellan.mcace.protocol.generated.FileEntry;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Objects;

public final class IntegrityDigests {
    private static final byte[] MANIFEST_DOMAIN = "mcace-manifest-v1\0".getBytes(StandardCharsets.UTF_8);

    private IntegrityDigests() {
    }

    public static byte[] scopeRoot(List<FileEntry> entries) {
        Objects.requireNonNull(entries, "entries");
        MessageDigest digest = sha256();
        digest.update(MANIFEST_DOMAIN);
        String previous = null;
        for (FileEntry entry : entries) {
            String path = entry.getRelativePath();
            if (path.isBlank() || entry.getFileSize() < 0 || entry.getSha256().size() != 32
                    || (previous != null && previous.compareTo(path) >= 0)) {
                throw new IllegalArgumentException("manifest entries must be valid and strictly path-sorted");
            }
            byte[] encodedPath = path.getBytes(StandardCharsets.UTF_8);
            digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(encodedPath.length).array());
            digest.update(encodedPath);
            digest.update(ByteBuffer.allocate(Long.BYTES).putLong(entry.getFileSize()).array());
            digest.update(entry.getSha256().toByteArray());
            previous = path;
        }
        return digest.digest();
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
