package com.ellan.mcace.client.integrity;

import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

public record IntegrityManifest(
        String scope,
        Instant capturedAt,
        List<IntegrityEntry> entries,
        byte[] rootSha256) {
    public IntegrityManifest {
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(capturedAt, "capturedAt");
        entries = List.copyOf(entries);
        Objects.requireNonNull(rootSha256, "rootSha256");
        if (scope.isBlank()) {
            throw new IllegalArgumentException("scope must not be blank");
        }
        if (rootSha256.length != 32) {
            throw new IllegalArgumentException("rootSha256 must contain 32 bytes");
        }
        rootSha256 = rootSha256.clone();
    }

    @Override
    public byte[] rootSha256() {
        return rootSha256.clone();
    }

    public String rootSha256Hex() {
        return HexFormat.of().formatHex(rootSha256);
    }
}
