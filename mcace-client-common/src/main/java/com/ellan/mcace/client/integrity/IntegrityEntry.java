package com.ellan.mcace.client.integrity;

import java.util.HexFormat;
import java.util.Objects;

public record IntegrityEntry(String relativePath, long fileSize, byte[] sha256) {
    public IntegrityEntry {
        Objects.requireNonNull(relativePath, "relativePath");
        Objects.requireNonNull(sha256, "sha256");
        if (relativePath.isBlank()) {
            throw new IllegalArgumentException("relativePath must not be blank");
        }
        if (fileSize < 0) {
            throw new IllegalArgumentException("fileSize must not be negative");
        }
        if (sha256.length != 32) {
            throw new IllegalArgumentException("sha256 must contain 32 bytes");
        }
        sha256 = sha256.clone();
    }

    @Override
    public byte[] sha256() {
        return sha256.clone();
    }

    public String sha256Hex() {
        return HexFormat.of().formatHex(sha256);
    }
}
