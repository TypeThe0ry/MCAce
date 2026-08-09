package com.ellan.mcace.protocol.launcher;

import com.ellan.mcace.protocol.generated.LauncherManifest;
import java.util.Objects;

public record LauncherVerification(
        LauncherManifest manifest,
        long trustSequence,
        boolean delegated,
        byte[] signerKeyIdSha256) {
    public LauncherVerification {
        Objects.requireNonNull(manifest, "manifest");
        if (trustSequence < 0 || signerKeyIdSha256 == null || signerKeyIdSha256.length != 32) {
            throw new IllegalArgumentException("invalid launcher verification metadata");
        }
        signerKeyIdSha256 = signerKeyIdSha256.clone();
    }

    @Override public byte[] signerKeyIdSha256() { return signerKeyIdSha256.clone(); }
}
