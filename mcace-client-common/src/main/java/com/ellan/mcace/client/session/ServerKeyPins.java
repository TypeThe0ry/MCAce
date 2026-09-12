package com.ellan.mcace.client.session;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HexFormat;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;

public final class ServerKeyPins {
    private final Map<String, PublicKey> pins;

    private ServerKeyPins(Map<String, PublicKey> pins) {
        this.pins = Map.copyOf(pins);
    }

    public static ServerKeyPins none() {
        return new ServerKeyPins(Map.of());
    }

    public static ServerKeyPins load(Path propertiesFile) throws IOException, EnvelopeException {
        Objects.requireNonNull(propertiesFile, "propertiesFile");
        if (!Files.exists(propertiesFile)) {
            return none();
        }
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(propertiesFile, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        Map<String, PublicKey> decoded = new HashMap<>();
        for (String name : properties.stringPropertyNames()) {
            String key = normalize(name);
            String value = properties.getProperty(name).trim();
            try {
                decoded.put(key, Ed25519Keys.decodePublic(Base64.getDecoder().decode(value)));
            } catch (IllegalArgumentException exception) {
                throw new EnvelopeException("invalid Base64 server key pin for " + name, exception);
            }
        }
        return new ServerKeyPins(decoded);
    }

    public Optional<PublicKey> find(String serverAddress) {
        Objects.requireNonNull(serverAddress, "serverAddress");
        PublicKey exact = pins.get(normalize(serverAddress));
        return Optional.ofNullable(exact != null ? exact : pins.get("default"));
    }

    /** Returns a stable diagnostic identifier without exposing key material. */
    public static String fingerprint(PublicKey key) {
        Objects.requireNonNull(key, "key");
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(key.getEncoded()));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    public boolean empty() {
        return pins.isEmpty();
    }

    private static String normalize(String value) {
        return value.trim().toLowerCase(Locale.ROOT);
    }
}
