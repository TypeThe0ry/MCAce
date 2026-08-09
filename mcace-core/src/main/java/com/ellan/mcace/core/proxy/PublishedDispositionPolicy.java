package com.ellan.mcace.core.proxy;

import java.util.HexFormat;
import java.util.Objects;

/** Immutable, non-secret audit result of an administrator policy publication. */
public record PublishedDispositionPolicy(String version, long sequence, byte[] documentSha256, int ruleCount) {
    public PublishedDispositionPolicy {
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(documentSha256, "documentSha256");
        if (version.isBlank() || sequence <= 0 || documentSha256.length != 32 || ruleCount < 0) {
            throw new IllegalArgumentException("invalid published disposition policy result");
        }
        documentSha256 = documentSha256.clone();
    }

    @Override public byte[] documentSha256() { return documentSha256.clone(); }
    public String documentSha256Hex() { return HexFormat.of().formatHex(documentSha256); }
}
