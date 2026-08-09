package com.ellan.mcace.launcher;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.LauncherFile;
import com.ellan.mcace.protocol.generated.LauncherManifest;
import com.ellan.mcace.protocol.generated.LauncherSigningKey;
import com.ellan.mcace.protocol.generated.LauncherTrustStatement;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.SignedLauncherManifest;
import com.ellan.mcace.protocol.generated.SignedLauncherTrustStatement;
import com.ellan.mcace.protocol.launcher.LauncherException;
import com.ellan.mcace.protocol.launcher.LauncherManifests;
import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class LauncherSecurityTest {
    private static final Instant NOW = Instant.parse("2026-08-08T13:00:00Z");
    private static final URI GAME_URI = URI.create("https://updates.example.test/releases/game.jar");
    @TempDir Path directory;
    private KeyPair root;
    private KeyPair releaseOne;
    private KeyPair releaseTwo;

    @BeforeEach
    void setUp() throws Exception {
        root = Ed25519Keys.generate(new SecureRandom());
        releaseOne = Ed25519Keys.generate(new SecureRandom());
        releaseTwo = Ed25519Keys.generate(new SecureRandom());
    }

    @Test
    void verifiesDelegatedReleaseAndRejectsTamperingUnsafePathsAndExpiry() throws Exception {
        byte[] content = "release-one".getBytes(StandardCharsets.UTF_8);
        SignedLauncherManifest signed = sign(releaseOne, trust(1, releaseOne, null), 1, "r1", content);
        var verified = LauncherManifests.verify(
                signed, root.getPublic(), Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofMinutes(1));
        assertEquals(1, verified.manifest().getReleaseSequence());
        assertTrue(verified.delegated());

        byte[] tampered = signed.getSignature().toByteArray();
        tampered[0] ^= 1;
        assertThrows(LauncherException.class, () -> LauncherManifests.verify(
                signed.toBuilder().setSignature(ByteString.copyFrom(tampered)).build(),
                root.getPublic(), Clock.fixed(NOW, ZoneOffset.UTC), Duration.ZERO));
        assertThrows(LauncherException.class, () -> LauncherManifests.verify(
                signed, root.getPublic(), Clock.fixed(NOW.plus(Duration.ofDays(2)), ZoneOffset.UTC),
                Duration.ZERO));

        LauncherManifest unsafe = manifest(2, "r2", content, releaseOne)
                .toBuilder().clearFiles().addFiles(file("../escape.jar", content)).build();
        assertThrows(LauncherException.class, () -> LauncherManifests.signDelegated(
                unsafe, releaseOne.getPrivate(), releaseOne.getPublic(), trust(1, releaseOne, null)));
    }

    @Test
    void cacheRejectsReleaseTrustAndClockRollbackAndSameSequenceEquivocation() throws Exception {
        Path cachePath = directory.resolve("state/launcher.pb");
        LauncherManifestCache cache = new LauncherManifestCache(
                cachePath, Clock.fixed(NOW, ZoneOffset.UTC));
        SignedLauncherTrustStatement firstTrust = trust(1, releaseOne, null);
        SignedLauncherTrustStatement secondTrust = trust(
                2, releaseTwo, LauncherManifests.keyId(releaseOne.getPublic()));
        cache.accept(sign(releaseOne, firstTrust, 1, "r1", bytes("one")), root.getPublic());
        cache.accept(sign(releaseTwo, secondTrust, 2, "r2", bytes("two")), root.getPublic());

        assertThrows(LauncherException.class, () -> cache.accept(
                sign(releaseOne, firstTrust, 1, "r1", bytes("one")), root.getPublic()));
        assertThrows(LauncherException.class, () -> cache.accept(
                sign(releaseOne, firstTrust, 999, "forged-future", bytes("old-key")), root.getPublic()));
        assertThrows(LauncherException.class, () -> cache.accept(
                sign(releaseTwo, secondTrust, 2, "r2-conflict", bytes("other")), root.getPublic()));
        assertThrows(LauncherException.class, () -> new LauncherManifestCache(
                cachePath, Clock.fixed(NOW.minus(Duration.ofMinutes(10)), ZoneOffset.UTC))
                .load(root.getPublic()));
        assertEquals(2, cache.load(root.getPublic()).orElseThrow().manifest().getReleaseSequence());

        SignedLauncherManifest requiresNewer = LauncherManifests.signDelegated(
                manifest(3, "r3", bytes("three"), releaseTwo).toBuilder()
                        .setMinimumLauncherVersion("0.2.0").build(),
                releaseTwo.getPrivate(), releaseTwo.getPublic(), secondTrust);
        assertThrows(LauncherException.class, () -> cache.accept(requiresNewer, root.getPublic()));
    }

    @Test
    void installsVerifiedFilesAtomicallyAndPreservesCurrentOnHashFailure() throws Exception {
        byte[] one = bytes("known-good-one");
        byte[] two = bytes("known-good-two");
        Map<URI, byte[]> downloads = new java.util.HashMap<>();
        downloads.put(GAME_URI, one);
        ContentFetcher fetcher = uri -> new ByteArrayInputStream(downloads.get(uri));
        LauncherInstaller installer = new LauncherInstaller(directory.resolve("install"), fetcher);
        VerifiedLauncherManifest first = verified(
                sign(releaseOne, trust(1, releaseOne, null), 1, "r1", one));
        Path current = installer.install(first);
        assertArrayEquals(one, Files.readAllBytes(current.resolve("game.jar")));
        assertFalse(Files.exists(directory.resolve("install/.mcace-staging")));

        downloads.put(GAME_URI, two);
        VerifiedLauncherManifest second = verified(
                sign(releaseOne, trust(1, releaseOne, null), 2, "r2", two));
        installer.install(second);
        assertArrayEquals(two, Files.readAllBytes(current.resolve("game.jar")));

        downloads.put(GAME_URI, bytes("corrupt"));
        VerifiedLauncherManifest third = verified(
                sign(releaseOne, trust(1, releaseOne, null), 3, "r3", bytes("expected")));
        assertThrows(LauncherException.class, () -> installer.install(third));
        assertArrayEquals(two, Files.readAllBytes(current.resolve("game.jar")));
    }

    @Test
    void recoversConservativelyFromCrashAfterBackupMove() throws Exception {
        Path rootPath = directory.resolve("recover");
        Path current = rootPath.resolve("current");
        Path backup = rootPath.resolve(".mcace-backup");
        Path stage = rootPath.resolve(".mcace-staging");
        Files.createDirectories(current);
        Files.writeString(current.resolve("old.txt"), "old");
        Files.createDirectory(stage);
        Files.writeString(stage.resolve("new.txt"), "new");
        Files.move(current, backup, StandardCopyOption.ATOMIC_MOVE);
        Files.writeString(rootPath.resolve(".mcace-update"),
                "version=1\nphase=BACKED_UP\nhad_current=true\n");

        new LauncherInstaller(rootPath, uri -> new ByteArrayInputStream(new byte[0])).recover();

        assertEquals("old", Files.readString(current.resolve("old.txt")));
        assertFalse(Files.exists(backup));
        assertFalse(Files.exists(stage));
        assertFalse(Files.exists(rootPath.resolve(".mcace-update")));
    }

    private VerifiedLauncherManifest verified(SignedLauncherManifest signed) throws Exception {
        var result = LauncherManifests.verify(
                signed, root.getPublic(), Clock.fixed(NOW, ZoneOffset.UTC), Duration.ZERO);
        return new VerifiedLauncherManifest(
                result.manifest(), signed, LauncherManifests.manifestDigest(signed),
                result.trustSequence(), result.delegated());
    }

    private SignedLauncherManifest sign(
            KeyPair key, SignedLauncherTrustStatement trust, long sequence, String release, byte[] content)
            throws Exception {
        return LauncherManifests.signDelegated(
                manifest(sequence, release, content, key), key.getPrivate(), key.getPublic(), trust);
    }

    private LauncherManifest manifest(long sequence, String release, byte[] content, KeyPair key)
            throws Exception {
        return LauncherManifest.newBuilder()
                .setSchemaVersion(1).setReleaseSequence(sequence).setProductId("mcace-official")
                .setReleaseId(release).setBuildId("fabric-phase4-" + release)
                .setMinecraftVersion("1.21.1").setLoader(LoaderType.FABRIC)
                .setMinimumLauncherVersion("0.1.0")
                .setIssuedAtEpochMs(NOW.minus(Duration.ofMinutes(1)).toEpochMilli())
                .setExpiresAtEpochMs(NOW.plus(Duration.ofDays(1)).toEpochMilli())
                .setSignerKeyIdSha256(ByteString.copyFrom(LauncherManifests.keyId(key.getPublic())))
                .addFiles(file("game.jar", content)).build();
    }

    private static LauncherFile file(String path, byte[] content) throws Exception {
        return LauncherFile.newBuilder().setRelativePath(path).setFileSize(content.length)
                .setSha256(ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(content)))
                .setDownloadUri(GAME_URI.toString()).build();
    }

    private SignedLauncherTrustStatement trust(long sequence, KeyPair key, byte[] revoked)
            throws Exception {
        LauncherTrustStatement.Builder value = LauncherTrustStatement.newBuilder()
                .setSequence(sequence).setProductId("mcace-official")
                .setIssuedAtEpochMs(NOW.minus(Duration.ofDays(1)).toEpochMilli())
                .setExpiresAtEpochMs(NOW.plus(Duration.ofDays(30)).toEpochMilli())
                .setRootKeyIdSha256(ByteString.copyFrom(LauncherManifests.keyId(root.getPublic())))
                .addReleaseSigningKeys(LauncherSigningKey.newBuilder()
                        .setKeyIdSha256(ByteString.copyFrom(LauncherManifests.keyId(key.getPublic())))
                        .setPublicKeyX509(ByteString.copyFrom(key.getPublic().getEncoded()))
                        .setNotBeforeEpochMs(NOW.minus(Duration.ofHours(1)).toEpochMilli())
                        .setNotAfterEpochMs(NOW.plus(Duration.ofDays(7)).toEpochMilli()));
        if (revoked != null) value.addRevokedKeyIdsSha256(ByteString.copyFrom(revoked));
        return LauncherManifests.signTrustStatement(value.build(), root.getPrivate(), root.getPublic());
    }

    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
}
