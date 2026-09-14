package com.ellan.mcace.client.integrity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class ScopedIntegrityScannerTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void producesStableRootIndependentOfCreationOrder() throws Exception {
        Path mods = Files.createDirectories(temporaryDirectory.resolve("mods"));
        Files.writeString(mods.resolve("z.jar"), "z");
        Files.writeString(mods.resolve("a.jar"), "a");
        ScopedIntegrityScanner scanner = new ScopedIntegrityScanner(Clock.systemUTC());

        IntegrityManifest first = scanner.scan(temporaryDirectory, Path.of("mods"), ScanPolicy.mods());
        IntegrityManifest second = scanner.scan(temporaryDirectory, Path.of("mods"), ScanPolicy.mods());

        assertEquals(first.rootSha256Hex(), second.rootSha256Hex());
        assertEquals("a.jar", first.entries().getFirst().relativePath());
    }

    @Test
    void rejectsScopeEscape() {
        ScopedIntegrityScanner scanner = new ScopedIntegrityScanner(Clock.systemUTC());
        assertThrows(
                IntegrityScanException.class,
                () -> scanner.scan(temporaryDirectory, Path.of(".."), ScanPolicy.mods()));
    }

    @Test
    void rejectsReparseOrSymlinkDirectoryBeforeEnumeration() throws Exception {
        Path scope = Files.createDirectories(temporaryDirectory.resolve("mods"));
        Path outside = Files.createDirectories(temporaryDirectory.resolve("outside"));
        Files.writeString(outside.resolve("redirected.jar"), "outside");
        Path link = scope.resolve("redirected");
        try {
            Files.createSymbolicLink(link, outside);
        } catch (IOException | UnsupportedOperationException | SecurityException exception) {
            assumeTrue(false, "symbolic-link creation unavailable: " + exception.getMessage());
        }

        ScopedIntegrityScanner scanner = new ScopedIntegrityScanner(Clock.systemUTC());
        assertThrows(IntegrityScanException.class,
                () -> scanner.scan(temporaryDirectory, Path.of("mods"), ScanPolicy.mods()));
    }

    @Test
    void cancellationAfterFirstChunkStopsLaterChunksAndFiles() throws Exception {
        byte[] content = new byte[(64 * 1024 * 2) + 17];
        Files.write(temporaryDirectory.resolve("a.txt"), content);
        Files.write(temporaryDirectory.resolve("b.txt"), content);
        CountDownLatch firstChunkRead = new CountDownLatch(1);
        CountDownLatch releaseFirstChunk = new CountDownLatch(1);
        AtomicInteger openedFiles = new AtomicInteger();
        AtomicInteger readChunks = new AtomicInteger();
        AtomicBoolean cancelled = new AtomicBoolean();
        ScopedIntegrityScanner scanner = new ScopedIntegrityScanner(Clock.systemUTC(), file -> {
            openedFiles.incrementAndGet();
            return new BlockingReadChannel(
                    FileChannel.open(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS),
                    readChunks, firstChunkRead, releaseFirstChunk);
        });
        ScanPolicy policy = new ScanPolicy(4, content.length, Set.of(".txt"));

        try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Future<?> scan = executor.submit(() -> {
                try {
                    scanner.scanExplicitFiles(temporaryDirectory, "explicit",
                            List.of("a.txt", "b.txt"), policy, true, cancelled::get);
                } catch (IntegrityScanException exception) {
                    throw new RuntimeException(exception);
                }
            });
            assertTrue(firstChunkRead.await(5, TimeUnit.SECONDS));
            cancelled.set(true);
            releaseFirstChunk.countDown();

            ExecutionException failure = assertThrows(
                    ExecutionException.class, () -> scan.get(5, TimeUnit.SECONDS));
            assertInstanceOf(IntegrityScanException.class, failure.getCause().getCause());
        } finally {
            releaseFirstChunk.countDown();
        }
        assertEquals(1, openedFiles.get(), "cancellation must prevent the second file from opening");
        assertEquals(1, readChunks.get(), "cancellation must be checked before the next 64 KiB read");
    }

    @Test
    void rejectsPathReplacementAfterOpeningTheNoFollowHandle() throws Exception {
        Path selected = temporaryDirectory.resolve("options.txt");
        Path replacement = temporaryDirectory.resolve("replacement.tmp");
        Files.writeString(selected, "old-value");
        Files.writeString(replacement, "replacement-value-with-a-distinct-size");
        AtomicBoolean replacementCompleted = new AtomicBoolean();
        ScopedIntegrityScanner scanner = new ScopedIntegrityScanner(Clock.systemUTC(), file -> {
            SeekableByteChannel opened = FileChannel.open(
                    file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
            try {
                Files.move(replacement, file, StandardCopyOption.REPLACE_EXISTING);
                replacementCompleted.set(true);
                return opened;
            } catch (IOException exception) {
                opened.close();
                throw exception;
            }
        });

        assertThrows(IntegrityScanException.class, () -> scanner.scanExplicitFiles(
                temporaryDirectory, "explicit", List.of("options.txt"),
                new ScanPolicy(1, 1024, Set.of(".txt")), true));
        assertTrue(replacementCompleted.get(), "fixture must replace the selected path after its handle opens");
    }

    @Test
    void rejectsAFirstHandleRedirectedAwayFromTheStableAuthorizedPath() throws Exception {
        Path selected = temporaryDirectory.resolve("options.txt");
        Path redirected = temporaryDirectory.resolve("outside.tmp");
        Files.writeString(selected, "authorized-content");
        Files.writeString(redirected, "redirected-content");
        assertEquals(Files.size(selected), Files.size(redirected));
        AtomicInteger opens = new AtomicInteger();
        ScopedIntegrityScanner scanner = new ScopedIntegrityScanner(Clock.systemUTC(), file ->
                FileChannel.open(opens.incrementAndGet() == 1 ? redirected : file,
                        StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));

        assertThrows(IntegrityScanException.class, () -> scanner.scanExplicitFiles(
                temporaryDirectory, "explicit", List.of("options.txt"),
                new ScanPolicy(1, 1024, Set.of(".txt")), true));
        assertEquals(2, opens.get(),
                "the independent no-follow verification read must detect a handle/path mismatch");
    }

    private static final class BlockingReadChannel implements SeekableByteChannel {
        private final SeekableByteChannel delegate;
        private final AtomicInteger readChunks;
        private final CountDownLatch firstChunkRead;
        private final CountDownLatch releaseFirstChunk;

        private BlockingReadChannel(SeekableByteChannel delegate, AtomicInteger readChunks,
                CountDownLatch firstChunkRead, CountDownLatch releaseFirstChunk) {
            this.delegate = delegate;
            this.readChunks = readChunks;
            this.firstChunkRead = firstChunkRead;
            this.releaseFirstChunk = releaseFirstChunk;
        }

        @Override
        public int read(ByteBuffer destination) throws IOException {
            int read = delegate.read(destination);
            if (read > 0 && readChunks.incrementAndGet() == 1) {
                firstChunkRead.countDown();
                try {
                    if (!releaseFirstChunk.await(5, TimeUnit.SECONDS)) {
                        throw new IOException("test did not release the first chunk");
                    }
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw new IOException("test read was interrupted", exception);
                }
            }
            return read;
        }

        @Override
        public int write(ByteBuffer source) throws IOException {
            throw new NonWritableChannelException();
        }

        @Override
        public long position() throws IOException {
            return delegate.position();
        }

        @Override
        public SeekableByteChannel position(long newPosition) throws IOException {
            delegate.position(newPosition);
            return this;
        }

        @Override
        public long size() throws IOException {
            return delegate.size();
        }

        @Override
        public SeekableByteChannel truncate(long size) throws IOException {
            throw new NonWritableChannelException();
        }

        @Override
        public boolean isOpen() {
            return delegate.isOpen();
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }
}
