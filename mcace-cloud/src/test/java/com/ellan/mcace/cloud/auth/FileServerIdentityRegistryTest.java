package com.ellan.mcace.cloud.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class FileServerIdentityRegistryTest {
    @TempDir Path temporaryDirectory;

    @Test
    void loadsAnExplicitEd25519IdentityAndScopes() throws Exception {
        byte[] publicKey = Ed25519Keys.generate(new SecureRandom()).getPublic().getEncoded();
        Path registry = temporaryDirectory.resolve("servers.registry");
        Files.writeString(registry, "velocity-a|" + Base64.getEncoder().encodeToString(publicKey)
                + "|RISK_WRITE,EVIDENCE_WRITE\n");

        ServerIdentity loaded = FileServerIdentityRegistry.load(registry).find("velocity-a").orElseThrow();

        assertEquals(2, loaded.scopes().size());
        assertEquals("EdDSA", loaded.publicKey().getAlgorithm());
    }

    @Test
    void rejectsDuplicateIdentities() throws Exception {
        String key = Base64.getEncoder().encodeToString(
                Ed25519Keys.generate(new SecureRandom()).getPublic().getEncoded());
        Path registry = temporaryDirectory.resolve("servers.registry");
        Files.writeString(registry, "velocity-a|" + key + "|RISK_WRITE\n"
                + "velocity-a|" + key + "|EVIDENCE_WRITE\n");

        assertThrows(java.io.IOException.class, () -> FileServerIdentityRegistry.load(registry));
    }
}
