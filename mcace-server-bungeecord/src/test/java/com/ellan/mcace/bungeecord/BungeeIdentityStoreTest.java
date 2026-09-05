package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class BungeeIdentityStoreTest {
    @TempDir Path temporaryDirectory;

    @Test
    void persistsStablePrivateIdentity() throws Exception {
        Path identityDirectory = temporaryDirectory.resolve("identity");
        KeyPair created = BungeeIdentityStore.loadOrCreate(identityDirectory);
        KeyPair loaded = BungeeIdentityStore.loadOrCreate(identityDirectory);

        assertArrayEquals(created.getPublic().getEncoded(), loaded.getPublic().getEncoded());
        assertArrayEquals(created.getPrivate().getEncoded(), loaded.getPrivate().getEncoded());
        assertTrue(Files.size(identityDirectory.resolve("server-public-key.txt")) > 0L);
        assertTrue(Files.size(identityDirectory.resolve("server-private-key.pk8")) > 0L);
    }

    @Test
    void rejectsIncompleteOversizedAndNonPrivateIdentityMaterial() throws Exception {
        Path identityDirectory = temporaryDirectory.resolve("identity-negative");
        BungeeIdentityStore.loadOrCreate(identityDirectory);
        Files.delete(identityDirectory.resolve("server-public-key.txt"));
        assertThrows(IOException.class,
                () -> BungeeIdentityStore.loadOrCreate(identityDirectory));

        Path oversizedDirectory = temporaryDirectory.resolve("identity-oversized");
        BungeeIdentityStore.loadOrCreate(oversizedDirectory);
        Files.write(oversizedDirectory.resolve("server-public-key.txt"), new byte[4097]);
        assertThrows(IOException.class,
                () -> BungeeIdentityStore.loadOrCreate(oversizedDirectory));

        Path ordinaryDirectory = temporaryDirectory.resolve("identity-ordinary");
        Files.createDirectory(ordinaryDirectory);
        assertThrows(IOException.class,
                () -> BungeeIdentityStore.loadOrCreate(ordinaryDirectory));
    }
}
