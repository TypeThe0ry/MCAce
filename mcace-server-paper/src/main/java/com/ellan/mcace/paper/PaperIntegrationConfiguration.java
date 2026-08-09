package com.ellan.mcace.paper;

import com.ellan.mcace.cloudclient.CloudClientConfiguration;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import org.bukkit.configuration.file.FileConfiguration;

record PaperIntegrationConfiguration(
        boolean behaviorEnabled,
        boolean grimEnabled,
        boolean vulcanEnabled,
        int minimumFlags,
        Duration window,
        Duration cooldown,
        int maximumKeys,
        CloudClientConfiguration cloud,
        BackendSessionActionConfiguration sessionActions) {

    static PaperIntegrationConfiguration load(FileConfiguration config, Path dataDirectory)
            throws IOException, EnvelopeException {
        boolean cloudEnabled = config.getBoolean("cloud.enabled", false);
        CloudClientConfiguration cloud = null;
        if (cloudEnabled) {
            String configuredPath = config.getString("cloud.private-key-path", "cloud-server-private-key.pk8");
            Path privateKeyPath = Path.of(configuredPath);
            if (!privateKeyPath.isAbsolute()) {
                privateKeyPath = dataDirectory.resolve(privateKeyPath).normalize();
            }
            cloud = new CloudClientConfiguration(
                    URI.create(required(config, "cloud.endpoint")),
                    required(config, "cloud.server-id"),
                    Ed25519Keys.decodePrivate(Files.readAllBytes(privateKeyPath)),
                    config.getInt("cloud.queue-capacity", 1024),
                    Duration.ofMillis(config.getLong("cloud.request-timeout-ms", 5000L)));
        }
        return new PaperIntegrationConfiguration(
                config.getBoolean("behavior.enabled", false),
                config.getBoolean("behavior.grim.enabled", true),
                config.getBoolean("behavior.vulcan.enabled", true),
                config.getInt("behavior.minimum-flags", 3),
                Duration.ofSeconds(config.getLong("behavior.window-seconds", 10L)),
                Duration.ofSeconds(config.getLong("behavior.cooldown-seconds", 30L)),
                config.getInt("behavior.maximum-tracked-keys", 10_000),
                cloud,
                BackendSessionActionConfiguration.parse(
                        config.getString("session-actions.mode", "MONITOR"),
                        config.getString("session-actions.limited-message",
                                BackendSessionActionConfiguration.DEFAULT_LIMITED_MESSAGE)));
    }

    private static String required(FileConfiguration config, String path) {
        String value = config.getString(path, "");
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(path + " must be configured when cloud.enabled=true");
        }
        return value.strip();
    }
}
