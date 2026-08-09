package com.ellan.mcace.launcher;

import com.ellan.mcace.protocol.generated.LauncherCacheState;
import com.ellan.mcace.protocol.generated.SignedLauncherManifest;
import com.ellan.mcace.protocol.launcher.LauncherException;
import com.ellan.mcace.protocol.launcher.LauncherManifests;
import com.ellan.mcace.protocol.launcher.LauncherVerification;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

public final class LauncherManifestCache {
    private static final int MAX_CACHE_BYTES = 8 * 1024 * 1024;
    private static final Duration CLOCK_ROLLBACK_TOLERANCE = Duration.ofMinutes(5);
    private final Path path;
    private final Clock clock;
    private final LauncherVersion launcherVersion;

    public LauncherManifestCache(Path path, Clock clock) {
        this(path, clock, "0.1.0");
    }

    public LauncherManifestCache(Path path, Clock clock, String launcherVersion) {
        this.path = Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
        this.clock = Objects.requireNonNull(clock, "clock");
        try {
            this.launcherVersion = LauncherVersion.parse(launcherVersion);
        } catch (LauncherException exception) {
            throw new IllegalArgumentException("current launcher version is invalid", exception);
        }
    }

    public synchronized VerifiedLauncherManifest accept(
            SignedLauncherManifest document, PublicKey pinnedRoot)
            throws IOException, LauncherException {
        Objects.requireNonNull(document, "document");
        LauncherVerification verified = LauncherManifests.verify(
                document, pinnedRoot, clock, Duration.ofMinutes(1));
        if (launcherVersion.compareTo(
                LauncherVersion.parse(verified.manifest().getMinimumLauncherVersion())) < 0) {
            throw new LauncherException("launcher update requires a newer launcher version");
        }
        Optional<Cached> existing = read(pinnedRoot, false);
        long now = clock.millis();
        if (existing.isPresent()) {
            Cached cached = existing.orElseThrow();
            rejectClockRollback(now, cached.acceptedAt());
            if (!cached.verified().manifest().getProductId().equals(verified.manifest().getProductId())) {
                throw new LauncherException("launcher product identity changed");
            }
            if (verified.manifest().getReleaseSequence()
                    < cached.verified().manifest().getReleaseSequence()) {
                throw new LauncherException("launcher release rollback detected");
            }
            if (verified.manifest().getReleaseSequence()
                    == cached.verified().manifest().getReleaseSequence()
                    && !MessageDigest.isEqual(
                            LauncherManifests.manifestDigest(document),
                            LauncherManifests.manifestDigest(cached.document()))) {
                throw new LauncherException("launcher manifest equivocation detected");
            }
            if (verified.trustSequence() < cached.verified().trustSequence()) {
                throw new LauncherException("launcher trust rollback detected");
            }
            if (verified.trustSequence() == cached.verified().trustSequence()
                    && !MessageDigest.isEqual(trustDigest(document), trustDigest(cached.document()))) {
                throw new LauncherException("launcher trust equivocation detected");
            }
        }
        byte[] encodedDocument = document.toByteArray();
        LauncherCacheState state = LauncherCacheState.newBuilder()
                .setDocument(document)
                .setAcceptedAtEpochMs(Math.max(now, existing.map(Cached::acceptedAt).orElse(now)))
                .setDocumentSha256(com.google.protobuf.ByteString.copyFrom(sha256(encodedDocument)))
                .build();
        if (state.getSerializedSize() > MAX_CACHE_BYTES) {
            throw new LauncherException("launcher cache document is too large");
        }
        atomicWrite(state.toByteArray());
        return result(verified, document);
    }

    public synchronized Optional<VerifiedLauncherManifest> load(PublicKey pinnedRoot)
            throws IOException, LauncherException {
        Optional<Cached> cached = read(pinnedRoot, true);
        if (cached.isEmpty()) return Optional.empty();
        rejectClockRollback(clock.millis(), cached.orElseThrow().acceptedAt());
        return Optional.of(result(cached.orElseThrow().verified(), cached.orElseThrow().document()));
    }

    private Optional<Cached> read(PublicKey root, boolean requireCurrent)
            throws IOException, LauncherException {
        if (!Files.exists(path)) return Optional.empty();
        byte[] bytes = Files.readAllBytes(path);
        if (bytes.length == 0 || bytes.length > MAX_CACHE_BYTES) {
            throw new LauncherException("launcher cache size is invalid");
        }
        LauncherCacheState state;
        try { state = LauncherCacheState.parseFrom(bytes); }
        catch (InvalidProtocolBufferException exception) {
            throw new LauncherException("launcher cache is malformed", exception);
        }
        byte[] document = state.getDocument().toByteArray();
        if (state.getAcceptedAtEpochMs() <= 0 || state.getDocumentSha256().size() != 32
                || !MessageDigest.isEqual(state.getDocumentSha256().toByteArray(), sha256(document))) {
            throw new LauncherException("launcher cache integrity check failed");
        }
        LauncherVerification verified = requireCurrent
                ? LauncherManifests.verify(state.getDocument(), root, clock, Duration.ofMinutes(1))
                : LauncherManifests.verifySignatureAndStructure(state.getDocument(), root);
        return Optional.of(new Cached(state.getDocument(), verified, state.getAcceptedAtEpochMs()));
    }

    private void atomicWrite(byte[] content) throws IOException {
        Files.createDirectories(path.getParent());
        Path temporary = Files.createTempFile(path.getParent(), path.getFileName().toString(), ".tmp");
        try {
            Files.write(temporary, content);
            try { Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE); }
            catch (AtomicMoveNotSupportedException exception) {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally { Files.deleteIfExists(temporary); }
    }

    private static VerifiedLauncherManifest result(
            LauncherVerification verification, SignedLauncherManifest document)
            throws LauncherException {
        return new VerifiedLauncherManifest(
                verification.manifest(), document, LauncherManifests.manifestDigest(document),
                verification.trustSequence(), verification.delegated());
    }

    private static byte[] trustDigest(SignedLauncherManifest document) throws LauncherException {
        return sha256(document.hasTrustStatement()
                ? document.getTrustStatement().toByteArray() : new byte[0]);
    }

    private static void rejectClockRollback(long now, long acceptedAt) throws LauncherException {
        if (now < acceptedAt - CLOCK_ROLLBACK_TOLERANCE.toMillis()) {
            throw new LauncherException("local clock rollback exceeds launcher tolerance");
        }
    }

    private static byte[] sha256(byte[] content) throws LauncherException {
        try { return MessageDigest.getInstance("SHA-256").digest(content); }
        catch (NoSuchAlgorithmException exception) { throw new LauncherException("SHA-256 is unavailable", exception); }
    }

    private record Cached(
            SignedLauncherManifest document, LauncherVerification verified, long acceptedAt) { }
}
