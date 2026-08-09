package com.ellan.mcace.velocity;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class ServerIdentityStoreTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void persistsStableServerIdentity() throws Exception {
        KeyPair created = ServerIdentityStore.loadOrCreate(temporaryDirectory);
        KeyPair loaded = ServerIdentityStore.loadOrCreate(temporaryDirectory);

        assertArrayEquals(created.getPublic().getEncoded(), loaded.getPublic().getEncoded());
        assertArrayEquals(created.getPrivate().getEncoded(), loaded.getPrivate().getEncoded());
        assertTrue(Files.size(temporaryDirectory.resolve("server-public-key.txt")) > 0);
        assertTrue(Files.size(temporaryDirectory.resolve("server-private-key.pk8")) > 0);
    }

    @Test
    void refusesIncompleteIdentity() throws Exception {
        ServerIdentityStore.loadOrCreate(temporaryDirectory);
        Files.delete(temporaryDirectory.resolve("server-public-key.txt"));

        assertThrows(IOException.class, () -> ServerIdentityStore.loadOrCreate(temporaryDirectory));
    }
}
