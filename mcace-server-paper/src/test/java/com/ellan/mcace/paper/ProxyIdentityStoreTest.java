package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class ProxyIdentityStoreTest {
    @TempDir Path temporaryDirectory;

    @Test
    void loadsPinnedEd25519PublicKey() throws Exception {
        KeyPair identity = Ed25519Keys.generate(new SecureRandom());
        Path pin = temporaryDirectory.resolve("velocity-public-key.txt");
        Files.writeString(pin, Base64.getEncoder().encodeToString(identity.getPublic().getEncoded()),
                StandardCharsets.US_ASCII);

        assertArrayEquals(identity.getPublic().getEncoded(), ProxyIdentityStore.load(pin).getEncoded());
    }

    @Test
    void failsClosedForMissingOrMalformedPin() throws Exception {
        Path missing = temporaryDirectory.resolve("missing").resolve("velocity-public-key.txt");
        assertThrows(IOException.class, () -> ProxyIdentityStore.load(missing));

        Path malformed = temporaryDirectory.resolve("velocity-public-key.txt");
        Files.writeString(malformed, "not-base64", StandardCharsets.US_ASCII);
        assertThrows(IOException.class, () -> ProxyIdentityStore.load(malformed));
    }
}
