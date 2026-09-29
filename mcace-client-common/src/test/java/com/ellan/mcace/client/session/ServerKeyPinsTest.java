package com.ellan.mcace.client.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class ServerKeyPinsTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void loadsExactAndDefaultPins() throws Exception {
        KeyPair exact = Ed25519Keys.generate(new SecureRandom());
        KeyPair fallback = Ed25519Keys.generate(new SecureRandom());
        Path file = temporaryDirectory.resolve("server-keys.properties");
        Files.writeString(file,
                "play.example.test=" + Base64.getEncoder().encodeToString(exact.getPublic().getEncoded()) + "\n"
                        + "default=" + Base64.getEncoder().encodeToString(fallback.getPublic().getEncoded()) + "\n");

        ServerKeyPins pins = ServerKeyPins.load(file);

        assertEquals(exact.getPublic(), pins.find("PLAY.EXAMPLE.TEST").orElseThrow());
        assertEquals(fallback.getPublic(), pins.find("other.example.test").orElseThrow());
    }

    @Test
    void exactLookupNeverFallsBackToDefault() throws Exception {
        KeyPair exact = Ed25519Keys.generate(new SecureRandom());
        KeyPair fallback = Ed25519Keys.generate(new SecureRandom());
        Path file = temporaryDirectory.resolve("server-keys.properties");
        Files.writeString(file,
                "play.example.test=" + Base64.getEncoder().encodeToString(exact.getPublic().getEncoded()) + "\n"
                        + "default=" + Base64.getEncoder().encodeToString(fallback.getPublic().getEncoded()) + "\n");

        ServerKeyPins pins = ServerKeyPins.load(file);

        assertEquals(exact.getPublic(), pins.findExact("Play.Example.Test").orElseThrow());
        assertTrue(pins.findExact("203.0.113.7:25565").isEmpty());
        // The 26.x client resolves the connected endpoint first, then the server-list address.
        assertEquals(exact.getPublic(), pins.findExact("203.0.113.7:25565")
                .or(() -> pins.find("play.example.test")).orElseThrow());
        assertEquals(fallback.getPublic(), pins.findExact("203.0.113.7:25565")
                .or(() -> pins.find("other.example.test")).orElseThrow());
    }

    @Test
    void missingFileProducesEmptyPins() throws Exception {
        ServerKeyPins pins = ServerKeyPins.load(temporaryDirectory.resolve("missing.properties"));
        assertTrue(pins.empty());
    }
}
