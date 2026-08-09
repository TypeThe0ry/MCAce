package com.ellan.mcace.cloud.auth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class CloudIdentityStoreTest {
    @TempDir Path temporaryDirectory;

    @Test
    void persistsAndReloadsAMatchingIdentity() throws Exception {
        KeyPair created = CloudIdentityStore.loadOrCreate(temporaryDirectory);
        KeyPair loaded = CloudIdentityStore.loadOrCreate(temporaryDirectory);

        assertArrayEquals(created.getPrivate().getEncoded(), loaded.getPrivate().getEncoded());
        assertArrayEquals(created.getPublic().getEncoded(), loaded.getPublic().getEncoded());
    }

    @Test
    void refusesAPartialIdentity() throws Exception {
        Files.write(temporaryDirectory.resolve("cloud-private-key.pk8"), new byte[] {1, 2, 3});

        assertThrows(java.io.IOException.class,
                () -> CloudIdentityStore.loadOrCreate(temporaryDirectory));
    }
}
