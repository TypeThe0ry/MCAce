package com.ellan.mcace.client.integrity;

import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

public record ScopeIntegrityManifest(
        String scope,
        String relativeRoot,
        boolean present,
        Instant capturedAt,
        List<IntegrityEntry> entries,
        byte[] rootSha256) {
    public ScopeIntegrityManifest {
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(relativeRoot, "relativeRoot");
        Objects.requireNonNull(capturedAt, "capturedAt");
        entries = List.copyOf(entries);
        Objects.requireNonNull(rootSha256, "rootSha256");
        if (scope.isBlank() || rootSha256.length != 32) {
            throw new IllegalArgumentException("scope and SHA-256 root are required");
        }
        if (!present && !entries.isEmpty()) {
            throw new IllegalArgumentException("absent scope cannot contain entries");
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
