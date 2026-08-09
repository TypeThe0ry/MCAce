package com.ellan.mcace.launcher;

import com.ellan.mcace.protocol.generated.LauncherManifest;
import com.ellan.mcace.protocol.generated.SignedLauncherManifest;
import java.util.Objects;

public record VerifiedLauncherManifest(
        LauncherManifest manifest,
        SignedLauncherManifest document,
        byte[] manifestSha256,
        long trustSequence,
        boolean delegated) {
    public VerifiedLauncherManifest {
        Objects.requireNonNull(manifest, "manifest");
        Objects.requireNonNull(document, "document");
        if (manifestSha256 == null || manifestSha256.length != 32 || trustSequence < 0) {
            throw new IllegalArgumentException("invalid verified launcher manifest");
        }
        manifestSha256 = manifestSha256.clone();
    }
    @Override public byte[] manifestSha256() { return manifestSha256.clone(); }
}
