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
        Path identityDirectory = temporaryDirectory.resolve("identity");
        KeyPair created = ServerIdentityStore.loadOrCreate(identityDirectory);
        KeyPair loaded = ServerIdentityStore.loadOrCreate(identityDirectory);

        assertArrayEquals(created.getPublic().getEncoded(), loaded.getPublic().getEncoded());
        assertArrayEquals(created.getPrivate().getEncoded(), loaded.getPrivate().getEncoded());
        assertTrue(Files.size(identityDirectory.resolve("server-public-key.txt")) > 0);
        assertTrue(Files.size(identityDirectory.resolve("server-private-key.pk8")) > 0);
    }

    @Test
    void refusesIncompleteIdentity() throws Exception {
        Path identityDirectory = temporaryDirectory.resolve("identity-incomplete");
        ServerIdentityStore.loadOrCreate(identityDirectory);
        Files.delete(identityDirectory.resolve("server-public-key.txt"));

        assertThrows(IOException.class, () -> ServerIdentityStore.loadOrCreate(identityDirectory));
    }

    @Test
    void refusesOversizedOrNonPrivateExistingIdentityMaterial() throws Exception {
        Path identityDirectory = temporaryDirectory.resolve("identity-negative");
        ServerIdentityStore.loadOrCreate(identityDirectory);
        Path publicKey = identityDirectory.resolve("server-public-key.txt");
        Files.write(publicKey, new byte[4097]);

        assertThrows(IOException.class, () -> ServerIdentityStore.loadOrCreate(identityDirectory));

        Path ordinaryDirectory = temporaryDirectory.resolve("ordinary-existing-identity");
        Files.createDirectory(ordinaryDirectory);
        assertThrows(IOException.class,
                () -> ServerIdentityStore.loadOrCreate(ordinaryDirectory));
    }
}
