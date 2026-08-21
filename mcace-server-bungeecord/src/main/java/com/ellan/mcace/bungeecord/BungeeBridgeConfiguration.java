package com.ellan.mcace.bungeecord;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;
import java.util.Properties;
import java.util.Locale;
import java.util.Optional;

/** Strict, deliberately small configuration for the built-in Fabric-first Bungee bridge. */
record BungeeBridgeConfiguration(
        String serverId,
        String minecraftVersion,
        String clientBuildId,
        Duration handshakeTimeout,
        BungeeDispositionExecutionMode dispositionExecutionMode,
        Optional<String> limitedServer,
        Optional<String> quarantineServer,
        com.ellan.mcace.core.session.HeartbeatMissingPolicy heartbeatMissingPolicy) {
    static final String DEFAULT_CONTENT = """
            # MCAce BungeeCord session bridge. Keep private keys in identity/, never in this file.
            # The built-in policy is Fabric-first. A custom bridge provider may be packaged when
            # compatibility requirements differ.
            server.id=mcace-bungeecord
            minecraft.version=1.21.11
            client.build-id=fabric-phase2-dev
            handshake.timeout.seconds=5
            disposition.enforcement.mode=MONITOR
            # LIMITED_ROUTE requires two distinct, registered Bungee servers. The legacy
            # disposition.restricted.server key is read only as a temporary LIMIT migration.
            # disposition.limited.server=limited
            # disposition.quarantine.server=quarantine
            heartbeat.missing.enabled=false
            heartbeat.missing.consecutive-polls=3
            heartbeat.missing.action=NOTICE
            """;

    BungeeBridgeConfiguration(
            String serverId, String minecraftVersion, String clientBuildId, Duration handshakeTimeout) {
        this(serverId, minecraftVersion, clientBuildId, handshakeTimeout,
                BungeeDispositionExecutionMode.MONITOR, Optional.empty(), Optional.empty(),
                com.ellan.mcace.core.session.HeartbeatMissingPolicy.disabled());
    }

    BungeeBridgeConfiguration(String serverId, String minecraftVersion, String clientBuildId, Duration handshakeTimeout,
            BungeeDispositionExecutionMode dispositionExecutionMode, String restrictedServer) {
        this(serverId, minecraftVersion, clientBuildId, handshakeTimeout, dispositionExecutionMode,
                optionalServer(restrictedServer), Optional.empty(),
                com.ellan.mcace.core.session.HeartbeatMissingPolicy.disabled());
    }

    BungeeBridgeConfiguration(String serverId, String minecraftVersion, String clientBuildId, Duration handshakeTimeout,
            BungeeDispositionExecutionMode dispositionExecutionMode, String limitedServer, String quarantineServer) {
        this(serverId, minecraftVersion, clientBuildId, handshakeTimeout, dispositionExecutionMode,
                optionalServer(limitedServer), optionalServer(quarantineServer),
                com.ellan.mcace.core.session.HeartbeatMissingPolicy.disabled());
    }

    BungeeBridgeConfiguration {
        Objects.requireNonNull(serverId, "serverId");
        Objects.requireNonNull(minecraftVersion, "minecraftVersion");
        Objects.requireNonNull(clientBuildId, "clientBuildId");
        Objects.requireNonNull(handshakeTimeout, "handshakeTimeout");
        Objects.requireNonNull(dispositionExecutionMode, "dispositionExecutionMode");
        Objects.requireNonNull(limitedServer, "limitedServer");
        Objects.requireNonNull(quarantineServer, "quarantineServer");
        Objects.requireNonNull(heartbeatMissingPolicy, "heartbeatMissingPolicy");
        if (!serverId.matches("[a-z0-9][a-z0-9._-]{0,63}")
                || minecraftVersion.isBlank()
                || clientBuildId.isBlank()
                || !validOptionalServer(limitedServer)
                || !validOptionalServer(quarantineServer)
                || handshakeTimeout.compareTo(Duration.ofSeconds(2)) < 0
                || handshakeTimeout.compareTo(Duration.ofSeconds(30)) > 0) {
            throw new IllegalArgumentException("invalid MCAce Bungee bridge configuration");
        }
    }

    static BungeeBridgeConfiguration loadOrCreate(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        Files.createDirectories(Objects.requireNonNull(path.getParent(), "configuration parent"));
        if (!Files.exists(path)) {
            Files.writeString(path, DEFAULT_CONTENT, StandardCharsets.UTF_8);
        }
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        int timeout;
        try {
            timeout = Integer.parseInt(properties.getProperty("handshake.timeout.seconds", "5").trim());
        } catch (NumberFormatException exception) {
            throw new IOException("invalid MCAce handshake.timeout.seconds", exception);
        }
        BungeeDispositionExecutionMode mode;
        try {
            mode = BungeeDispositionExecutionMode.valueOf(
                    properties.getProperty("disposition.enforcement.mode", "MONITOR")
                            .trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new IOException("invalid MCAce disposition.enforcement.mode", exception);
        }
        try {
            return new BungeeBridgeConfiguration(
                    properties.getProperty("server.id", "mcace-bungeecord").trim(),
                    properties.getProperty("minecraft.version", "1.21.11").trim(),
                    properties.getProperty("client.build-id", "fabric-phase2-dev").trim(),
                    Duration.ofSeconds(timeout),
                    mode,
                    limitedServer(properties),
                    optionalProperty(properties, "disposition.quarantine.server"),
                    new com.ellan.mcace.core.session.HeartbeatMissingPolicy(
                            parseBoolean(properties.getProperty("heartbeat.missing.enabled", "false"), "heartbeat.missing.enabled"),
                            Integer.parseInt(properties.getProperty("heartbeat.missing.consecutive-polls", "3").trim()),
                            com.ellan.mcace.core.session.HeartbeatMissingPolicy.Action.valueOf(
                                    properties.getProperty("heartbeat.missing.action", "NOTICE").trim().toUpperCase(Locale.ROOT))));
        } catch (IllegalArgumentException exception) {
            throw new IOException("invalid MCAce Bungee bridge configuration", exception);
        }
    }

    private static boolean parseBoolean(String value, String name) throws IOException {
        if ("true".equalsIgnoreCase(value.trim())) return true;
        if ("false".equalsIgnoreCase(value.trim())) return false;
        throw new IOException("invalid MCAce " + name);
    }

    /** Legacy compatibility is intentionally one-way: restricted may supply LIMIT, never QUARANTINE. */
    private static Optional<String> limitedServer(Properties properties) {
        Optional<String> explicit = optionalProperty(properties, "disposition.limited.server");
        return explicit.isPresent() ? explicit : optionalProperty(properties, "disposition.restricted.server");
    }

    private static Optional<String> optionalProperty(Properties properties, String key) {
        if (!properties.containsKey(key)) {
            return Optional.empty();
        }
        return optionalServer(properties.getProperty(key));
    }

    private static Optional<String> optionalServer(String value) {
        String normalized = Objects.requireNonNull(value, "server").trim();
        return normalized.isEmpty() ? Optional.empty() : Optional.of(normalized);
    }

    private static boolean validOptionalServer(Optional<String> server) {
        return server.isEmpty() || server.orElseThrow().matches("[a-z0-9][a-z0-9._-]{0,63}");
    }
}
