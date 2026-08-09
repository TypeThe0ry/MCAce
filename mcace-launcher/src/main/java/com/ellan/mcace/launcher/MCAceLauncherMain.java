package com.ellan.mcace.launcher;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.SignedLauncherManifest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;

public final class MCAceLauncherMain {
    private MCAceLauncherMain() { }

    public static void main(String[] args) throws Exception {
        if (args.length != 4 || !"verify".equals(args[0])) {
            throw new IllegalArgumentException(
                    "usage: verify <signed-manifest.pb> <root-public-x509.der> <cache.pb>");
        }
        SignedLauncherManifest document = SignedLauncherManifest.parseFrom(Files.readAllBytes(Path.of(args[1])));
        var root = Ed25519Keys.decodePublic(Files.readAllBytes(Path.of(args[2])));
        var accepted = new LauncherManifestCache(Path.of(args[3]), Clock.systemUTC()).accept(document, root);
        System.out.println("verified release=" + accepted.manifest().getReleaseId()
                + " sequence=" + accepted.manifest().getReleaseSequence()
                + " files=" + accepted.manifest().getFilesCount());
    }
}
