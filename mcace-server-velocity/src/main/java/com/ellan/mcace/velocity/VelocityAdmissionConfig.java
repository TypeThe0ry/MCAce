package com.ellan.mcace.velocity;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;

record VelocityAdmissionConfig(
        Mode mode,
        Optional<String> limitedServer,
        Optional<String> quarantineServer,
        Duration handshakeTimeout,
        HeartbeatMissingConfig heartbeatMissing,
        StorageConfig storage,
        PolicyConfig policy) {
    private static final String DEFAULT_CONTENT = """
            # MONITOR records state only. LIMITED_ROUTE is enabled only when both distinct targets
            # below are explicitly configured and registered with this Velocity proxy.
            enforcement.mode=MONITOR
            # LIMIT routes only to disposition.limited.server.
            # disposition.limited.server=limited-backend
            # QUARANTINE never inherits the LIMIT target; configure a separate registered backend.
            # disposition.quarantine.server=quarantine-backend
            handshake.timeout.seconds=5
            # Disabled by default. STALE never acts; after this many continuous MISSING polls,
            # action is only NOTICE or LIMITED_ROUTE and a valid heartbeat reverses it.
            heartbeat.missing.enabled=false
            heartbeat.missing.consecutive-polls=3
            heartbeat.missing.action=NOTICE
            # These values are signed into the Fabric client policy. Change them before
            # publishing a release build; comma-separated lists are supported.
            policy.server-id=mcace-velocity
            policy.minecraft-versions=1.21.11
            policy.client-build-ids=fabric-phase2-dev
            # PostgreSQL audit storage is opt-in. Keep credentials out of this file.
            storage.enabled=false
            storage.jdbc-url=jdbc:postgresql://127.0.0.1:5432/mcace
            storage.username=mcace
            storage.password-env=MCACE_DB_PASSWORD
            storage.migrate-on-start=true
            """;

    VelocityAdmissionConfig {
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(limitedServer, "limitedServer");
        Objects.requireNonNull(quarantineServer, "quarantineServer");
        Objects.requireNonNull(handshakeTimeout, "handshakeTimeout");
        Objects.requireNonNull(heartbeatMissing, "heartbeatMissing");
        Objects.requireNonNull(storage, "storage");
        Objects.requireNonNull(policy, "policy");
        if (handshakeTimeout.compareTo(Duration.ofSeconds(2)) < 0
                || handshakeTimeout.compareTo(Duration.ofSeconds(30)) > 0) {
            throw new IllegalArgumentException("handshake timeout must be between 2 and 30 seconds");
        }
    }

    static VelocityAdmissionConfig loadOrCreate(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        Files.createDirectories(path.getParent());
        if (!Files.exists(path)) {
            Files.writeString(path, DEFAULT_CONTENT, StandardCharsets.UTF_8);
        }
        Properties properties = new Properties();
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        String configuredMode = properties.getProperty("enforcement.mode", "MONITOR")
                .trim().toUpperCase(Locale.ROOT);
        Mode mode;
        try {
            mode = Mode.valueOf(configuredMode);
        } catch (IllegalArgumentException exception) {
            throw new IOException("invalid MCAce enforcement.mode: " + configuredMode, exception);
        }
        Optional<String> limitedServer = configuredServer(
                properties, "disposition.limited.server", "limited.server");
        Optional<String> quarantineServer = configuredServer(
                properties, "disposition.quarantine.server", "quarantine.server");
        int timeoutSeconds;
        try {
            timeoutSeconds = Integer.parseInt(properties.getProperty("handshake.timeout.seconds", "5").trim());
        } catch (NumberFormatException exception) {
            throw new IOException("invalid MCAce handshake.timeout.seconds", exception);
        }
        try {
            StorageConfig storage = new StorageConfig(
                    parseBoolean(properties.getProperty("storage.enabled", "false"), "storage.enabled"),
                    properties.getProperty("storage.jdbc-url", "jdbc:postgresql://127.0.0.1:5432/mcace").trim(),
                    properties.getProperty("storage.username", "mcace").trim(),
                    properties.getProperty("storage.password-env", "MCACE_DB_PASSWORD").trim(),
                    parseBoolean(properties.getProperty("storage.migrate-on-start", "true"),
                            "storage.migrate-on-start"));
            PolicyConfig policy = new PolicyConfig(
                    properties.getProperty("policy.server-id", "mcace-velocity").trim(),
                    parseList(properties.getProperty("policy.minecraft-versions", "1.21.11"),
                            "policy.minecraft-versions"),
                    parseList(properties.getProperty("policy.client-build-ids", "fabric-phase2-dev"),
                            "policy.client-build-ids"));
            return new VelocityAdmissionConfig(
                    mode, limitedServer, quarantineServer, Duration.ofSeconds(timeoutSeconds),
                    new HeartbeatMissingConfig(
                            parseBoolean(properties.getProperty("heartbeat.missing.enabled", "false"), "heartbeat.missing.enabled"),
                            Integer.parseInt(properties.getProperty("heartbeat.missing.consecutive-polls", "3").trim()),
                            com.ellan.mcace.core.session.HeartbeatMissingPolicy.Action.valueOf(
                                    properties.getProperty("heartbeat.missing.action", "NOTICE").trim().toUpperCase(Locale.ROOT))),
                    storage, policy);
        } catch (IllegalArgumentException exception) {
            throw new IOException("invalid MCAce admission configuration", exception);
        }
    }

    enum Mode {
        MONITOR,
        LIMITED_ROUTE
    }

    record HeartbeatMissingConfig(boolean enabled, int consecutivePolls,
            com.ellan.mcace.core.session.HeartbeatMissingPolicy.Action action) {
        HeartbeatMissingConfig {
            Objects.requireNonNull(action, "action");
            new com.ellan.mcace.core.session.HeartbeatMissingPolicy(enabled, consecutivePolls, action);
        }
        com.ellan.mcace.core.session.HeartbeatMissingPolicy toPolicy() {
            return new com.ellan.mcace.core.session.HeartbeatMissingPolicy(enabled, consecutivePolls, action);
        }
    }

    private static boolean parseBoolean(String value, String name) throws IOException {
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        if ("true".equals(normalized)) return true;
        if ("false".equals(normalized)) return false;
        throw new IOException("invalid MCAce " + name + ": " + value);
    }

    /**
     * A target is present only when an operator set its property. The unprefixed key is a
     * one-way compatibility alias for the same action; it is never inferred for another action.
     * Ambiguous aliases are rejected instead of choosing one silently.
     */
    private static Optional<String> configuredServer(
            Properties properties, String canonicalName, String legacyName) throws IOException {
        boolean canonicalPresent = properties.containsKey(canonicalName);
        boolean legacyPresent = properties.containsKey(legacyName);
        if (!canonicalPresent && !legacyPresent) {
            return Optional.empty();
        }
        String canonical = canonicalPresent ? properties.getProperty(canonicalName).trim() : "";
        String legacy = legacyPresent ? properties.getProperty(legacyName).trim() : "";
        if ((canonicalPresent && canonical.isBlank()) || (legacyPresent && legacy.isBlank())) {
            throw new IOException("invalid MCAce disposition route target");
        }
        if (canonicalPresent && legacyPresent && !canonical.equals(legacy)) {
            throw new IOException("conflicting MCAce disposition route aliases");
        }
        return Optional.of(canonicalPresent ? canonical : legacy);
    }

    private static List<String> parseList(String value, String name) throws IOException {
        List<String> values = java.util.Arrays.stream(value.split(",", -1))
                .map(String::trim)
                .toList();
        if (values.isEmpty() || values.size() > 32 || values.stream().anyMatch(String::isBlank)
                || values.stream().distinct().count() != values.size()
                || values.stream().anyMatch(entry -> entry.length() > 128 || entry.chars().anyMatch(Character::isISOControl))) {
            throw new IOException("invalid MCAce " + name);
        }
        return List.copyOf(values);
    }

    record PolicyConfig(String serverId, List<String> minecraftVersions, List<String> clientBuildIds) {
        PolicyConfig {
            Objects.requireNonNull(serverId, "serverId");
            minecraftVersions = List.copyOf(Objects.requireNonNull(minecraftVersions, "minecraftVersions"));
            clientBuildIds = List.copyOf(Objects.requireNonNull(clientBuildIds, "clientBuildIds"));
            if (!serverId.matches("[a-z0-9][a-z0-9._-]{0,63}")
                    || minecraftVersions.isEmpty() || clientBuildIds.isEmpty()) {
                throw new IllegalArgumentException("invalid signed policy release metadata");
            }
        }
    }

    record StorageConfig(
            boolean enabled,
            String jdbcUrl,
            String username,
            String passwordEnvironmentVariable,
            boolean migrateOnStart) {
        StorageConfig {
            Objects.requireNonNull(jdbcUrl, "jdbcUrl");
            Objects.requireNonNull(username, "username");
            Objects.requireNonNull(passwordEnvironmentVariable, "passwordEnvironmentVariable");
            if (enabled && (!jdbcUrl.startsWith("jdbc:postgresql:")
                    || username.isBlank()
                    || !passwordEnvironmentVariable.matches("[A-Z][A-Z0-9_]{1,63}"))) {
                throw new IllegalArgumentException("invalid PostgreSQL storage configuration");
            }
        }
    }
}
